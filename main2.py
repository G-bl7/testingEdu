#!/usr/bin/env python3
"""Recursive, bandwidth-limited FTP uploader.

- NEVER STOPS, NEVER GIVES UP: files are retried forever on network errors
  (use Ctrl+C to abort).
- AUTO-RESUME: every successfully uploaded file is recorded in a state file.
  On restart, the uploader reads the state file (CLI input) and skips all
  already-uploaded files, continuing from where it left off.
"""

import argparse
import getpass
import hashlib
import json
import os
import sys
import tempfile
import time
from datetime import datetime
from ftplib import FTP, error_perm
from pathlib import Path, PurePosixPath

SKIP_EXTENSIONS = frozenset({".js", ".css", ".html", ".scss"})
SKIP_DIRECTORIES = frozenset({".git"})
BLOCK_SIZE = 64 * 1024
DEFAULT_STATE_DIR = Path(tempfile.gettempdir()) / "ftp_upload_state"


def log(message):
    print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {message}", flush=True)


class Throttle:
    """Per-file rate limiter. Only counts time spent transferring, so
    delays/cooldowns between files never cause a burst afterwards."""

    def __init__(self, kbps):
        self.rate = kbps * 1024
        self.reset()

    def reset(self):
        self.t0 = time.monotonic()
        self.sent = 0

    def __call__(self, block):
        self.sent += len(block)
        if self.rate:
            delay = self.sent / self.rate - (time.monotonic() - self.t0)
            if delay > 0:
                time.sleep(delay)


class StateFile:
    """Persistent record of successfully uploaded files.

    Keys are relative POSIX paths, values are {"size": int, "mtime": float}.
    Saved atomically (tmp file + os.replace) after every upload."""

    def __init__(self, path):
        self.path = Path(path)
        self.data = {}
        if self.path.exists():
            try:
                self.data = json.loads(self.path.read_text(encoding="utf-8"))
                log(f"[RESUME] Loaded state: {len(self.data)} file(s) already uploaded")
            except (OSError, ValueError) as e:
                log(f"[WARNING] Could not read state file {self.path} ({e}); starting fresh")
                self.data = {}

    def is_done(self, rel_path, size, mtime):
        rec = self.data.get(rel_path)
        return rec is not None and rec.get("size") == size and rec.get("mtime") == mtime

    def mark_done(self, rel_path, size, mtime):
        self.data[rel_path] = {"size": size, "mtime": mtime}
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(json.dumps(self.data, indent=1, sort_keys=True), encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError as e:
            log(f"[WARNING] Could not save state file: {e}")


class Stats:
    def __init__(self):
        self.start = time.monotonic()
        self.files = 0
        self.resumed = 0
        self.skipped = 0
        self.failed = 0
        self.bytes = 0

    def elapsed(self):
        return max(time.monotonic() - self.start, 0.001)

    def speed_kbs(self):
        return self.bytes / self.elapsed() / 1024


class Uploader:
    def __init__(self, args, local_root):
        self.args = args
        self.local_root = local_root
        self.stats = Stats()
        self.throttle = Throttle(args.limit_kbps)
        self.ftp = None
        self.cwd = None          # absolute remote directory we are currently in
        self.state = StateFile(args.state_file)

    # ---------------- connection ----------------

    def connect(self):
        a = self.args
        ftp = FTP()
        ftp.encoding = "utf-8"  # non-ASCII file names
        ftp.connect(a.host, a.port, timeout=60)
        ftp.login(a.username, a.password)
        ftp.set_pasv(True)
        self.ftp = ftp
        self.cwd = None

    def close(self):
        if self.ftp is None:
            return
        try:
            self.ftp.quit()
        except Exception:
            self.ftp.close()
        self.ftp = None

    def reconnect(self, wait=5):
        log(f"[RECONNECT] Reconnecting in {wait}s...")
        try:
            if self.ftp:
                self.ftp.close()
        except Exception:
            pass
        while True:  # never give up: keep trying until the server answers
            try:
                self.connect()
                log("[+] Reconnected and authenticated")
                return
            except (OSError, EOFError) as e:
                log(f"[RETRY CONNECT] {e}; retrying in {wait}s...")
                time.sleep(wait)

    # ---------------- remote directories ----------------

    def ensure_dir(self, path):
        """cwd into `path`, creating any missing parents. One round trip
        when the directory already exists."""
        try:
            self.ftp.cwd(str(path))
        except error_perm:
            if path == path.parent:
                raise
            self.ensure_dir(path.parent)
            self.ftp.mkd(path.name)
            log(f"[DIRECTORY CREATED] {path}")
            self.ftp.cwd(str(path))
        self.cwd = path

    def enter(self, path):
        if self.cwd != path:
            self.ensure_dir(path)

    def remote_sizes(self):
        """{filename: size} of the current remote directory (needs MLSD)."""
        try:
            return {
                name: int(facts["size"])
                for name, facts in self.ftp.mlsd(facts=["type", "size"])
                if facts.get("type") == "file" and "size" in facts
            }
        except (error_perm, ValueError, AttributeError):
            return {}

    # ---------------- upload ----------------

    def skip(self, item, reason):
        self.stats.skipped += 1
        log(f"[SKIP] {item} | Reason: {reason} | Total skipped: {self.stats.skipped}")

    def upload_file(self, path, size, remote_dir):
        """Upload one file. NEVER GIVES UP: network errors are retried
        forever until the file is on the server or the user aborts."""
        attempt = 0
        while True:  # infinite retries: never stop, never give up
            attempt += 1
            try:
                self.enter(remote_dir)
                self.throttle.reset()
                with path.open("rb") as f:
                    self.ftp.storbinary(
                        f"STOR {path.name}", f, BLOCK_SIZE, self.throttle
                    )
                return True
            except error_perm as e:  # permanent (permissions, quota...): no retry
                log(f"[FAILED] {path} | {e}")
                return False
            except KeyboardInterrupt:
                raise
            except (OSError, EOFError) as e:  # network/local I/O: retry forever
                log(f"[RETRY {attempt}] {path} | {e}")
                time.sleep(2)
                self.reconnect()

    def upload_dir(self, local_dir, remote_dir):
        a = self.args
        log(f"[SCANNING] {local_dir}")

        files, dirs = [], []
        with os.scandir(local_dir) as it:
            for e in sorted(it, key=lambda e: e.name):
                if e.is_symlink():
                    self.skip(e.path, "Symbolic link")
                elif e.is_dir(follow_symlinks=False):
                    if e.name in SKIP_DIRECTORIES:
                        self.skip(e.path, "Excluded directory")
                    else:
                        dirs.append(e)
                elif e.is_file(follow_symlinks=False):
                    ext = os.path.splitext(e.name)[1].lower()
                    if ext in SKIP_EXTENSIONS:
                        self.skip(e.path, f"Excluded extension: {ext}")
                    else:
                        files.append(e)

        if files:
            self.enter(remote_dir)
            existing = self.remote_sizes() if a.skip_existing else {}

            for e in files:
                full = Path(e.path)
                rel = full.relative_to(self.local_root).as_posix()
                st = e.stat()
                size, mtime = st.st_size, st.st_mtime

                # Resume: already uploaded in a previous run -> skip instantly
                if self.state.is_done(rel, size, mtime):
                    self.stats.resumed += 1
                    log(f"[RESUMED] {rel} | Already uploaded (from state file)")
                    continue

                if existing.get(e.name) == size:
                    self.skip(e.path, "Already on server (same size)")
                    self.state.mark_done(rel, size, mtime)
                    continue

                if self.upload_file(full, size, remote_dir):
                    s = self.stats
                    s.files += 1
                    s.bytes += size
                    self.state.mark_done(rel, size, mtime)  # save progress NOW
                    log(
                        f"[UPLOADED] {e.name} | Files: {s.files} | "
                        f"Resumed: {s.resumed} | Skipped: {s.skipped} | "
                        f"Total: {s.bytes / 1024 / 1024:.2f} MB | "
                        f"Speed: {s.speed_kbs():.1f} KB/s"
                    )
                else:
                    self.stats.failed += 1

                if a.file_delay:
                    time.sleep(a.file_delay)

                if a.batch_size and self.stats.files and self.stats.files % a.batch_size == 0:
                    log(f"[BATCH COMPLETE] {self.stats.files} files, pausing {a.batch_pause}s")
                    time.sleep(a.batch_pause)

        for e in dirs:
            log(f"[ENTERING DIRECTORY] {e.name}")
            self.upload_dir(e.path, remote_dir / e.name)

    def run(self):
        a = self.args
        self.reconnect(wait=0)
        log("[+] Connected and authenticated")

        # Base = <login dir> / remote_dir / <full local path>
        remote_base = PurePosixPath(self.ftp.pwd())
        extra = a.remote_dir.replace("\\", "/").strip("/")
        if extra:
            remote_base /= extra
        for part in self.local_root.parts:
            if part not in (self.local_root.anchor, "/", ""):
                remote_base /= part.replace(":", "")  # "C:" -> "C" on Windows

        log(f"[*] Remote destination: {remote_base}")
        self.ensure_dir(remote_base)
        self.upload_dir(self.local_root, remote_base)


def default_state_file(host, local_dir):
    """Auto state file name: stable per host + local folder."""
    key = hashlib.sha1(f"{host}|{local_dir}".encode()).hexdigest()[:10]
    return DEFAULT_STATE_DIR / f"upload_state_{key}.json"


def parse_args():
    p = argparse.ArgumentParser(
        description="Timestamped, rate-limited recursive FTP uploader "
                    "(never stops, auto-resumes from state file)")
    p.add_argument("host", help="FTP server")
    p.add_argument("local_dir", help="Local folder")
    p.add_argument("remote_dir", help="Remote FTP base directory")
    p.add_argument("-u", "--username", default="anonymous")
    p.add_argument("-P", "--password", help="Password (default: $FTP_PASSWORD, else prompt)")
    p.add_argument("-p", "--port", type=int, default=21)
    p.add_argument("--limit-kbps", type=float, default=512, help="Bandwidth limit in KB/s (0 = unlimited)")
    p.add_argument("--file-delay", type=float, default=0.1, help="Delay between files in seconds")
    p.add_argument("--batch-size", type=int, default=100, help="Pause after this many files (0 = disabled)")
    p.add_argument("--batch-pause", type=float, default=3, help="Pause between batches in seconds")
    p.add_argument("--state-file", default=None,
                   help="Resume state file (input). Default: auto-generated in temp dir")
    p.add_argument("--no-resume", action="store_true",
                   help="Ignore the state file and re-upload everything")
    p.add_argument("--skip-existing", action="store_true",
                   help="Skip files already on the server with the same size (resume)")
    args = p.parse_args()

    if min(args.limit_kbps, args.file_delay, args.batch_size, args.batch_pause) < 0:
        p.error("Limits and delays cannot be negative")

    local_dir = str(Path(args.local_dir).expanduser().resolve())
    if args.state_file is None:
        args.state_file = str(default_state_file(args.host, local_dir))
    if args.no_resume:
        args.state_file = os.devnull  # state writes become no-ops, reads find nothing

    if args.password is None:
        args.password = os.environ.get("FTP_PASSWORD")
    if args.password is None:
        if args.username == "anonymous":
            args.password = "anonymous@"
        else:
            args.password = getpass.getpass(f"Password for {args.username}: ")
    return args


def main():
    args = parse_args()

    local_root = Path(args.local_dir).expanduser().resolve()
    if not local_root.is_dir():
        sys.exit(f"[ERROR] Directory not found: {local_root}")

    log(f"[*] Server: {args.host}:{args.port} | Local: {local_root}")
    log(f"[*] State file: {args.state_file}")
    log(f"[*] Limit: {args.limit_kbps} KB/s | Excluded ext: {', '.join(sorted(SKIP_EXTENSIONS))} "
        f"| Excluded dirs: {', '.join(sorted(SKIP_DIRECTORIES))}")

    up = Uploader(args, local_root)
    interrupted = False
    try:
        up.run()
    except KeyboardInterrupt:
        interrupted = True
        log("[STOPPED] Upload interrupted by user")
    except Exception as e:
        log(f"[ERROR] Upload failed: {e}")
    finally:
        up.close()
        s = up.stats
        log("=" * 38)
        status = "[SUCCESS] UPLOAD FINISHED" if not interrupted and s.failed == 0 else "[INCOMPLETE] Upload did not finish successfully"
        log(status)
        log(f"Uploaded: {s.files} | Resumed: {s.resumed} | Skipped: {s.skipped} | Failed: {s.failed}")
        log(f"Total: {s.bytes / 1024 / 1024:.2f} MB | Avg speed: {s.speed_kbs():.2f} KB/s | "
            f"Duration: {s.elapsed():.1f}s")
        log(f"Progress saved to: {args.state_file}")
        log("=" * 38)

    sys.exit(0 if not interrupted and up.stats.failed == 0 else 1)


if __name__ == "__main__":
    main()
