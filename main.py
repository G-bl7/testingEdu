
#!/usr/bin/env python3
"""Recursive, bandwidth-limited FTP uploader."""

import argparse
import getpass
import os
import sys
import time
from datetime import datetime
from ftplib import FTP, error_perm
from pathlib import Path, PurePosixPath

SKIP_EXTENSIONS = frozenset({".js", ".css", ".html", ".scss"})
SKIP_DIRECTORIES = frozenset({".git"})
BLOCK_SIZE = 64 * 1024


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

    def reconnect(self):
        log("[RECONNECT] Connection lost, reconnecting...")
        try:
            if self.ftp:
                self.ftp.close()
        except Exception:
            pass
        self.connect()

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
        a = self.args
        for attempt in range(a.retries + 1):
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
            except (OSError, EOFError) as e:  # network/local I/O: retry
                log(f"[RETRY {attempt + 1}/{a.retries}] {path} | {e}")
                if attempt == a.retries:
                    return False
                time.sleep(2)
                self.reconnect()
                self.cwd = None
        return False

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
                size = e.stat().st_size
                if existing.get(e.name) == size:
                    self.skip(e.path, "Already on server (same size)")
                    continue

                if self.upload_file(Path(e.path), size, remote_dir):
                    s = self.stats
                    s.files += 1
                    s.bytes += size
                    log(
                        f"[UPLOADED] {e.name} | Files: {s.files} | "
                        f"Skipped: {s.skipped} | "
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
        self.connect()
        log("[+] Connected and authenticated")

        # Base = <login dir> / remote_dir / <full local path>
        # (the local path is recreated under the remote base, as before)
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


def parse_args():
    p = argparse.ArgumentParser(description="Timestamped, rate-limited recursive FTP uploader")
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
    p.add_argument("--retries", type=int, default=3, help="Retries per file on network errors")
    p.add_argument("--skip-existing", action="store_true",
                   help="Skip files already on the server with the same size (resume)")
    args = p.parse_args()

    if min(args.limit_kbps, args.file_delay, args.batch_size, args.batch_pause, args.retries) < 0:
        p.error("Limits, delays and retries cannot be negative")

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
        log(f"Uploaded: {s.files} | Skipped: {s.skipped} | Failed: {s.failed}")
        log(f"Total: {s.bytes / 1024 / 1024:.2f} MB | Avg speed: {s.speed_kbs():.2f} KB/s | "
            f"Duration: {s.elapsed():.1f}s")
        log("=" * 38)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

