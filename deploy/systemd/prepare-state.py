#!/usr/bin/python3
"""Prepare private state and remove only a demonstrably stale analyzer lock."""

import os
from pathlib import Path
import re
import stat
import sys


LOCK_NAME = "analyzer.lock"


def fingerprint(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def prepare_state(value):
    if not value or not Path(value).is_absolute():
        raise ValueError("DUMP_ANALYZER_STATE_DIR must be an absolute path")
    state_dir = Path(value)
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory_fd = os.open(state_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        try:
            before = os.stat(LOCK_NAME, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return "state ready; no lock present"
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
        ):
            raise ValueError("refusing lock that is not an owned regular file with one link")
        lock_fd = os.open(
            LOCK_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd
        )
        try:
            if fingerprint(os.fstat(lock_fd)) != fingerprint(before):
                raise ValueError("lock changed while opening it")
            content = os.read(lock_fd, 65)
            match = re.fullmatch(rb"pid=([1-9][0-9]*)\n", content)
            if match is None:
                raise ValueError("refusing malformed lock; expected pid=N followed by newline")
            pid = int(match[1])
            if pid > 2**31 - 1:
                raise ValueError("refusing lock with an out-of-range PID")
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                pass
            else:
                raise ValueError(f"lock PID {pid} is still alive")
            current = os.stat(LOCK_NAME, dir_fd=directory_fd, follow_symlinks=False)
            if fingerprint(current) != fingerprint(before):
                raise ValueError("lock changed while checking its PID")
            os.unlink(LOCK_NAME, dir_fd=directory_fd)
            return f"removed stale lock for absent PID {pid}"
        finally:
            os.close(lock_fd)
    finally:
        os.close(directory_fd)


def main():
    try:
        result = prepare_state(os.environ.get("DUMP_ANALYZER_STATE_DIR"))
    except (OSError, ValueError) as error:
        print(f"dump-analyzer state preparation failed: {error}", file=sys.stderr)
        return 1
    print(f"dump-analyzer: {result}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
