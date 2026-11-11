#!/usr/bin/env python3
""" v1 Recursive, bandwidth-limited FTP uploader that never gives up.

- Retries forever on ANY network/I/O failure AND on temporary server errors
  (4xx, e.g. "421 too many connections") with reconnect + backoff.
- Connections are always closed cleanly (QUIT) so the server frees the slot.
- A NOOP keepalive before every file detects dead connections early.
- --start-file LIST: a local text file with one filename per line.
  Files whose names appear in the list are skipped. Uploading starts at
  the file whose name matches the list file's own basename (that file is
  uploaded too), and continues through the rest of the tree.
"""

import argparse
import getpass
import os
import sys
import time
from datetime import datetime
from ftplib import FTP, error_perm, error_proto, error_temp
from pathlib import Path, PurePosixPath

SKIP_EXTENSIONS = frozenset({".js", ".css", ".html", ".scss"})
SKIP_DIRECTORIES = frozenset({".git"})
BLOCK_SIZE = 64 * 1024
MAX_BACKOFF = 60        # seconds, normal reconnect backoff
MAX_BUSY_WAIT = 600     # seconds, wait when server says "too many connections"

# Everything that should trigger "reconnect and try again".
RETRYABLE = (OSError, EOFError, error_temp, error_proto)


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


class Stats:
    def __init__(self):
        self.start = time.monotonic()
        self.files = 0
        self.skipped = 0
        self.failed = 0
        self.bytes = 0
        self.reconnects = 0

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
        self.cwd = None  # absolute remote directory we are currently in
        # --- start-file logic ---
        self.started = args.start_file is None
        self.skip_names = set()
        self.marker_name = None
        if args.start_file:
            self.marker_name = os.path.basename(args.start_file)
            try:
                with open(args.start_file, "r", encoding="utf-8", errors="replace") as f:
                    self.skip_names = {
                        line.strip() for line in f
                        if line.strip() and not line.lstrip().startswith("#")
                    }
                log(f"[*] Start-file: {args.start_file} | "
                    f"{len(self.skip_names)} names to skip | marker: {self.marker_name}")
            except OSError as e:
                sys.exit(f"[ERROR] Cannot read start-file: {e}")

    # ---------------- connection ----------------

    def _connect_once(self):
        a = self.args
        ftp = FTP()
        ftp.encoding = "utf-8"  # non-ASCII file names
        try:
            ftp.connect(a.host, a.port, timeout=60)
            ftp.login(a.username, a.password)
            ftp.set_pasv(True)
        except BaseException:
            # Never leave a half-open session behind: it counts against the
            # server's per-IP connection limit.
            self._drop(ftp)
            raise
        self.ftp = ftp
        self.cwd = None

    @staticmethod
    def _drop(ftp):
        """Close a connection as cleanly as possible so the server frees the slot."""
        if ftp is None:
            return
        try:
            ftp.sock.settimeout(5)  # don't hang on a dead socket
        except Exception:
            pass
        try:
            ftp.quit()
        except Exception:
            try:
                ftp.close()
            except Exception:
                pass

    def close(self):
        self._drop(self.ftp)
        self.ftp = None

    def connect_forever(self):
        """Connect + login, retrying forever on network errors and 4xx replies.
        A permanent error (e.g. 530 bad password) is NOT retried."""
        tries = 0
        while True:
            try:
                self._connect_once()
                return
            except error_perm:
                raise  # wrong credentials etc. - retrying will not help
            except error_temp as e:  # 421 too many connections, etc.
                tries += 1
                wait = min(60 * tries, MAX_BUSY_WAIT)
                log(f"[SERVER BUSY] {e} | waiting {wait}s for old sessions to expire")
                time.sleep(wait)
            except (OSError, EOFError, error_proto) as e:
                tries += 1
                wait = min(2 ** min(tries, 8), MAX_BACKOFF)
                log(f"[RETRY CONNECT] {self.args.host}:{self.args.port} | {e} | in {wait}s")
                time.sleep(wait)

    def reconnect(self, attempt=1):
        wait = min(2 ** min(attempt, 8), MAX_BACKOFF)
        self.stats.reconnects += 1
        log(f"[RECONNECT #{self.stats.reconnects}] Connection lost, retrying in {wait}s...")
        self.close()  # QUIT the old session first
        time.sleep(wait)
        self.connect_forever()
        log("[RECONNECTED] Login OK")

    def keepalive(self):
        """Raises if the connection is dead, so the caller reconnects."""
        self.ftp.voidcmd("NOOP")

    # ---------------- start-file gate ----------------

    def check_start(self, name):
        """Returns True if `name` may be uploaded, False if it must be skipped."""
        if self.started:
            return True
        if name in self.skip_names:
            self.stats.skipped += 1
            log(f"[SKIP] {name} | Reason: on start-file list | "
                f"Total skipped: {self.stats.skipped}")
            return False
        if name == self.marker_name:
            log(f"[START] Marker file '{name}' found - uploads begin now")
            self.started = True
            return True
        # Not on the list and not the marker: before the resume point,
        # so it has already been uploaded in a previous run.
        self.stats.skipped += 1
        log(f"[SKIP] {name} | Reason: before resume point | "
            f"Total skipped: {self.stats.skipped}")
        return False

    # ---------------- remote directories ----------------

    def ensure_dir(self, path, attempt=0):
        """cwd into `path`, creating any missing parents. Retries forever."""
        try:
            self.ftp.cwd(str(path))
            self.cwd = path
        except error_perm:
            if path == path.parent:
                raise
            self.ensure_dir(path.parent)
            try:
                self.ftp.mkd(path.name)
                log(f"[DIRECTORY CREATED] {path}")
            except error_perm:
                pass  # probably created meanwhile; cwd below will tell
            self.ftp.cwd(str(path))
            self.cwd = path
        except RETRYABLE as e:
            attempt += 1
            log(f"[RETRY DIR] {path} | {e}")
            self.reconnect(attempt)
            self.ensure_dir(path, attempt)

    def enter(self, path):
        if self.cwd != path:
            self.ensure_dir(path)

    def remote_sizes(self, remote_dir):
        """{filename: size} of `remote_dir` (needs MLSD)."""
        attempt = 0
        while True:
            try:
                self.enter(remote_dir)
                return {
                    name: int(facts["size"])
                    for name, facts in self.ftp.mlsd(facts=["type", "size"])
                    if facts.get("type") == "file" and "size" in facts
                }
            except (error_perm, ValueError, AttributeError):
                return {}  # MLSD unsupported
            except RETRYABLE as e:
                attempt += 1
                log(f"[RETRY LISTING] | {e}")
                self.reconnect(attempt)

    # ---------------- upload ----------------

    def skip(self, item, reason):
        self.stats.skipped += 1
        log(f"[SKIP] {item} | Reason: {reason} | Total skipped: {self.stats.skipped}")

    def upload_file(self, path, remote_dir):
        """Upload one file. Retries FOREVER on network/local I/O errors
        and temporary (4xx) server errors."""
        attempt = 0
        while True:
            try:
                self.enter(remote_dir)
                self.keepalive()
                self.throttle.reset()
                with path.open("rb") as f:
                    self.ftp.storbinary(
                        f"STOR {path.name}", f, BLOCK_SIZE, self.throttle
                    )
                return True
            except error_perm as e:  # permanent (permissions, quota...): no retry
                log(f"[FAILED] {path} | {e}")
                return False
            except RETRYABLE as e:  # network/local I/O/4xx: retry forever
                attempt += 1
                log(f"[RETRY {attempt}] {path} | {e}")
                self.reconnect(attempt)

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
            # Directory must exist before any upload, no matter what.
            attempt = 0
            while True:
                try:
                    self.enter(remote_dir)
                    break
                except RETRYABLE as e:
                    attempt += 1
                    log(f"[RETRY ENTER] {remote_dir} | {e}")
                    self.reconnect(attempt)
            existing = self.remote_sizes(remote_dir) if a.skip_existing else {}

            for e in files:
                name = e.name
                s = self.stats

                # Start-file gate: skip until the marker file is found.
                if not self.check_start(name):
                    continue

                size = e.stat().st_size
                if existing.get(name) == size:
                    self.skip(e.path, "Already on server (same size)")
                    continue

                if self.upload_file(Path(e.path), remote_dir):
                    s.files += 1
                    s.bytes += size
                    log(
                        f"[UPLOADED] {name} | Files: {s.files} | "
                        f"Skipped: {s.skipped} | "
                        f"Total: {s.bytes / 1024 / 1024:.2f} MB | "
                        f"Speed: {s.speed_kbs():.1f} KB/s"
                    )
                else:
                    s.failed += 1  # permanent error: record, keep going

                if a.file_delay:
                    time.sleep(a.file_delay)

                if a.batch_size and s.files and s.files % a.batch_size == 0:
                    log(f"[BATCH COMPLETE] {s.files} files, pausing {a.batch_pause}s")
                    time.sleep(a.batch_pause)

        for e in dirs:
            log(f"[ENTERING DIRECTORY] {e.name}")
            self.upload_dir(e.path, remote_dir / e.name)

    def run(self):
        a = self.args
        self.connect_forever()
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

        if not self.started and self.marker_name is not None:
            log(f"[NOTE] Marker '{self.marker_name}' was never found - "
                f"everything matched the skip list / was already uploaded.")


def parse_args():
    p = argparse.ArgumentParser(
        description="Never-give-up, rate-limited recursive FTP uploader with start-file resume"
    )
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
    p.add_argument("--retries", type=int, default=3,
                   help="(deprecated, ignored) uploads now retry forever")
    p.add_argument("--skip-existing", action="store_true",
                   help="Skip files already on the server with the same size (resume)")
    p.add_argument("--start-file", metavar="LIST",
                   help="Text file with one filename per line. Skip all listed files; "
                        "uploads begin at the file named like this list file itself, "
                        "then continue through everything after it.")
    args = p.parse_args()

    if min(args.limit_kbps, args.file_delay, args.batch_size, args.batch_pause) < 0:
        p.error("Limits, delays and pauses cannot be negative")

    if args.start_file and not os.path.isfile(args.start_file):
        p.error(f"Start-file not found: {args.start_file}")

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
    log(f"[*] Limit: {args.limit_kbps} KB/s | Excluded ext: {', '.join(sorted(SKIP_EXTENSIONS))} "
        f"| Excluded dirs: {', '.join(sorted(SKIP_DIRECTORIES))}")

    up = Uploader(args, local_root)
    success = False
    try:
        up.run()
        success = up.stats.failed == 0
    except KeyboardInterrupt:
        log("[STOPPED] Upload interrupted by user")
    except Exception as e:
        log(f"[ERROR] Upload failed: {e}")
    finally:
        up.close()
        s = up.stats
        log("=" * 38)
        log("[SUCCESS] UPLOAD FINISHED" if success else "[INCOMPLETE] Upload did not finish successfully")
        log(f"Uploaded: {s.files} | Skipped: {s.skipped} | Failed: {s.failed} | Reconnects: {s.reconnects}")
        log(f"Total: {s.bytes / 1024 / 1024:.2f} MB | Avg speed: {s.speed_kbs():.2f} KB/s | "
            f"Duration: {s.elapsed():.1f}s")
        log("=" * 38)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
