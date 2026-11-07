"""Durable device-side marker shared by readers and the print backend.

The caller holds the common USB lock before entering. Only an explicitly
verified completion clears the marker; process death or an exception retains it.
"""
import datetime as dt
import json
import os
from pathlib import Path
import stat

DEFAULT_GUARD_FILE='/var/lib/hp-plotter/captures/transaction-unverified.json'


class UnverifiedTransport(RuntimeError):pass


def guard_path(config):
    return Path(config.get('device_guard_file',DEFAULT_GUARD_FILE))


def sync_directory(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:os.fsync(fd)
    finally:os.close(fd)


class DeviceGuard:
    def __init__(self,path,kind):
        self.path=Path(path);self.kind=kind;self.cleared=False;self.identity=None
        if not self.path.is_absolute() or not isinstance(kind,str) or len(kind)>100:
            raise ValueError('guard needs an absolute path and a short operation label')

    def __enter__(self):
        self.path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        parent=self.path.parent.stat()
        if parent.st_uid!=os.geteuid() or parent.st_mode & 0o022:
            raise RuntimeError('device guard directory must be owned by its caller and not writable by others')
        try:fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        except FileExistsError:
            raise UnverifiedTransport('previous USB transaction needs inspection; no new operation started') from None
        with os.fdopen(fd,'w') as out:
            info=os.fstat(out.fileno());self.identity=(info.st_dev,info.st_ino)
            json.dump({'version':1,'kind':self.kind,'pid':os.getpid(),
                'started_utc':dt.datetime.now(dt.timezone.utc).isoformat()},out)
            out.write('\n');out.flush();os.fsync(out.fileno())
        sync_directory(self.path.parent)
        return self

    def clear(self):
        info=os.lstat(self.path)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1
                or (info.st_dev,info.st_ino)!=self.identity or info.st_mode & 0o077):
            raise RuntimeError('device guard identity changed; refusing to clear it')
        self.path.unlink();sync_directory(self.path.parent);self.cleared=True

    def __exit__(self,*exc):
        return False
