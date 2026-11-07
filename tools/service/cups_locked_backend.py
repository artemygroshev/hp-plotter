"""Per-queue CUPS wrapper: serialize native USB backend with read-only queries.

No print bytes are parsed or rewritten. stdin/stdout/stderr and CUPS channel
FDs 3/4 are inherited. The parent retains the lock until its child is reaped.
Only the native USB backend may send print data; it is never replaced globally.
"""
import ctypes
from contextlib import nullcontext
import fcntl
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time
from access_lock import usb_lock
from local_config import idle_binding
from device_guard import DeviceGuard,guard_path
from usb_idle import ensure_idle

NATIVE_BACKEND='/usr/lib/cups/backend/usb'


def private_json(path):
    path=Path(path)
    info=path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022:
        raise RuntimeError('backend configuration must be root-owned and not writable by others')
    return json.loads(path.read_text())


def child_setup(parent):
    # The CUPS scheduler normally terminates a process group. Also stop the
    # child if the wrapper alone dies; a subsequent reader checks open handles.
    for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(sig,signal.SIG_DFL)
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.prctl(1,signal.SIGTERM,0,0,0)!=0 or os.getppid()!=parent:
        os._exit(1)


def forward(argv,native_uri,lock_file,backend=NATIVE_BACKEND,wait_seconds=90,before=None,after=None,guard_file=None):
    if len(argv) not in (6,7) or not native_uri.startswith('usb://HP/') or '\n' in native_uri:
        raise ValueError('expected a CUPS job and a configured native HP USB URI')
    channels=[]
    for fd in (3,4):
        try:os.fstat(fd);channels.append(fd)
        except OSError:pass
    cancelled=[False];child=[None];old={}
    def cancel(sig,frame):
        cancelled[0]=True
        if child[0] is not None and child[0].poll() is None:child[0].send_signal(sig)
    for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):old[sig]=signal.signal(sig,cancel)
    began=time.monotonic()
    try:
        while not cancelled[0] and time.monotonic()-began<wait_seconds:
            try:
                with usb_lock(lock_file) as lock_fd:
                    if cancelled[0]:return 5
                    transaction=DeviceGuard(guard_file,'print:'+str(argv[1])) if guard_file else nullcontext(None)
                    with transaction as lease:
                        started=False;preparation_attempted=False;preparation_verified=False
                        try:
                            if cancelled[0]:return 5
                            if before is not None:
                                preparation_attempted=True;before();preparation_verified=True
                            if cancelled[0]:return 5
                            env=os.environ.copy();env['DEVICE_URI']=native_uri
                            parent=os.getpid()
                            inherited_lock=fcntl.fcntl(lock_fd,fcntl.F_DUPFD_CLOEXEC,5)
                            try:
                                child[0]=subprocess.Popen([native_uri]+list(argv[1:]),executable=backend,
                                    env=env,pass_fds=tuple(channels+[inherited_lock]),preexec_fn=lambda:child_setup(parent))
                                started=True
                            finally:os.close(inherited_lock)
                            cancel_at=None
                            while child[0].poll() is None:
                                if cancelled[0]:
                                    if cancel_at is None:cancel_at=time.monotonic()
                                    if time.monotonic()-cancel_at>10:child[0].kill()
                                time.sleep(.1)
                            rc=child[0].wait()
                        finally:
                            if child[0] is not None and child[0].poll() is None:
                                child[0].terminate()
                                try:child[0].wait(10)
                                except subprocess.TimeoutExpired:child[0].kill();child[0].wait()
                            if started and after is not None:after()
                            if (not started and lease is not None
                                    and (not preparation_attempted or preparation_verified)):
                                lease.clear()
                        if rc==0 and not cancelled[0] and lease is not None:lease.clear()
                        return 5 if cancelled[0] else (rc if 0<=rc<=7 else 1)
            except BlockingIOError:time.sleep(.1)
        return 5 if cancelled[0] else 6
    finally:
        if child[0] is not None and child[0].poll() is None:
            child[0].terminate()
            try:child[0].wait(10)
            except subprocess.TimeoutExpired:child[0].kill();child[0].wait()
        for sig,handler in old.items():signal.signal(sig,handler)


def ownership_guards(config):
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'firmware'))
    import status_snapshot as support
    support.MACHINE_ID=config['machine_id'];support.ADAPTER_DESCRIPTOR_SHA256=config['adapter_descriptor_sha256']
    support.QUEUE=config['queue'];support.URI='ipp://localhost:631/printers/'+config['queue']
    expected_driver,expected_alt=idle_binding(config)
    saved=[]
    def current():
        rows=support.adapters()
        if len(rows)!=1 or rows[0]['descriptor_sha256']!=config['adapter_descriptor_sha256']:
            raise RuntimeError('pinned USB adapter missing or ambiguous')
        handles=support.adapter_open_handles(rows)
        if handles['open_handles'] or not handles['inspection_complete']:
            raise RuntimeError('USB interface is owned by another process')
        return rows[0]
    def before():
        ensure_idle(support.__dict__,config,allow_queued_job=True)
        row=current()
        if row['driver']!=expected_driver or row['alternate']!=expected_alt:
            raise RuntimeError('USB ownership is not in its recorded idle state')
        saved[:]=[row]
    def after():
        row=current()
        if not saved or any(row[key]!=saved[0][key] for key in ('path','busnum','devnum')):
            raise RuntimeError('USB adapter changed during the native job')
        if row['driver'] is None and expected_driver is not None:
            # The upstream 1a86:7584 quirk can intentionally leave usblp
            # detached. Rebind only our unchanged, now unowned interface.
            interface=Path(row['sysfs_node']).name+':1.0'
            Path('/sys/bus/usb/drivers/usblp/bind').write_text(interface)
            row=current()
        if row['driver']!=expected_driver or row['alternate']!=expected_alt:
            raise RuntimeError('native backend did not restore the idle interface')
    return before,after


def main():
    if len(sys.argv)==1:
        print('direct hpplotter:/usb "HP DesignJet 500" "HP DesignJet 500, coordinated USB access"')
        return 0
    if os.environ.get('DEVICE_URI')!='hpplotter:/usb':
        raise RuntimeError('unexpected wrapper device URI')
    config=private_json('/etc/hp-plotter/config.json')
    backend=private_json('/etc/hp-plotter/backend.json')
    if Path('/etc/machine-id').read_text().strip()!=config['machine_id']:
        raise RuntimeError('BTT identity differs from the installation pin')
    before,after=ownership_guards(config)
    return forward(sys.argv,backend['native_uri'],config['lock_file'],before=before,after=after,guard_file=guard_path(config))


if __name__=='__main__':
    try:sys.exit(main())
    except Exception as error:
        print('ERROR: HP USB coordination failed: '+str(error),file=sys.stderr)
        sys.exit(4)
