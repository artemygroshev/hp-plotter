"""One root-owned advisory lock used by both the collector and CUPS backend.

The lock covers one complete USB transaction, including interface restoration.
Queue checks still apply: queued jobs take priority at the next transaction.
Uncooperating direct USB programs are detected by the existing ownership scan.
"""
from contextlib import contextmanager
import fcntl
import os
import stat


@contextmanager
def usb_lock(path, blocking=False):
    if not os.path.isabs(path):
        raise ValueError('USB lock path must be absolute')
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
            raise RuntimeError('unsafe USB lock ownership or file type')
        if info.st_mode & 0o077:
            raise RuntimeError('USB lock must be private to its owner')
        fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        try:
            yield fd
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)
