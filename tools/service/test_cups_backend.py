"""Native process/FD/cancellation tests; stdlib only, no printer I/O."""
import os
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from access_lock import usb_lock
from device_guard import DeviceGuard,UnverifiedTransport
from cups_locked_backend import forward

SERVICE=Path(__file__).resolve().parent


class BackendChecks(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.stub=self.root/'native';self.stub.write_text('''#!/usr/bin/python3
import json,os,signal,sys,time
from pathlib import Path
root=Path(os.environ['TEST_ROOT'])
(root/'started').write_text(str(os.getpid()))
(root/'args.json').write_text(json.dumps({'args':sys.argv[1:],'uri':os.environ['DEVICE_URI']}))
if os.environ.get('TEST_CANCEL'):
 signal.signal(signal.SIGTERM,lambda *args:(time.sleep(.6),sys.exit(0)))
 (root/'ready').write_text('ready')
 while True:time.sleep(.1)
data=Path(sys.argv[6]).read_bytes() if len(sys.argv)==7 else sys.stdin.buffer.read()
os.write(3,b'back-channel');os.write(4,b'side-channel')
sys.stdout.buffer.write(data);sys.stdout.buffer.flush()
sys.exit(int(os.environ.get('TEST_EXIT','7')))
''');self.stub.chmod(0o700)
        self.lock=str(self.root/'usb.lock')

    def tearDown(self):self.temp.cleanup()

    def test_failed_preparation_keeps_guard_even_before_native_launch(self):
        guard=self.root/'guard.json'
        def partial_preparation():raise RuntimeError('idle preparation cleanup unverified')
        with self.assertRaisesRegex(RuntimeError,'preparation cleanup'):
            forward(['hpplotter:/usb','17','u','title','1',''],
                'usb://HP/DesignJet',self.lock,backend=str(self.stub),
                before=partial_preparation,guard_file=guard)
        self.assertTrue(guard.exists());self.assertFalse((self.root/'started').exists())

    def test_cancel_during_verified_preparation_never_launches_native_child(self):
        guard=self.root/'guard.json'
        def cancelled_preparation():os.kill(os.getpid(),signal.SIGTERM)
        result=forward(['hpplotter:/usb','17','u','title','1',''],
            'usb://HP/DesignJet',self.lock,backend=str(self.stub),
            before=cancelled_preparation,guard_file=guard)
        self.assertEqual(result,5);self.assertFalse(guard.exists())
        self.assertFalse((self.root/'started').exists())

    def launch(self,filename=None,cancel=False,guard_file=None,exit_code=7):
        args=['hpplotter:/usb','17','unit-user','title with spaces','1','media=Custom.610x200mm']
        if filename:args.append(str(filename))
        source="""import os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from cups_locked_backend import forward
root=Path(os.environ['TEST_ROOT'])
import contextlib,cups_locked_backend
original_lock=cups_locked_backend.usb_lock
@contextlib.contextmanager
def ready_lock(*args,**kwargs):
 (root/'lock-attempt').touch()
 with original_lock(*args,**kwargs) as fd:yield fd
cups_locked_backend.usb_lock=ready_lock
back=os.open(root/'back',os.O_WRONLY|os.O_CREAT,0o600)
os.dup2(back,3)
side=os.open(root/'side',os.O_WRONLY|os.O_CREAT,0o600)
os.dup2(side,4)
sys.exit(forward(%r,'usb://HP/DesignJet%%20500%%20(C7769B)',%r,backend=%r,wait_seconds=10,guard_file=%r))
"""%(args,self.lock,str(self.stub),str(guard_file) if guard_file is not None else None)
        env=os.environ.copy();env['TEST_ROOT']=str(self.root)
        env['TEST_EXIT']=str(exit_code)
        if cancel:env['TEST_CANCEL']='1'
        return subprocess.Popen([sys.executable,'-c',source,str(SERVICE)],stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)

    def test_backend_preserves_binary_payload_arguments_channels_and_exit_status(self):
        payload=bytes(range(256))*33
        for use_file in (False,True):
            path=self.root/'input';path.write_bytes(payload)
            p=self.launch(path if use_file else None)
            out,err=p.communicate(b'' if use_file else payload,timeout=5)
            self.assertEqual(p.returncode,7,err)
            self.assertEqual(out,payload)
            self.assertEqual((self.root/'back').read_bytes(),b'back-channel')
            self.assertEqual((self.root/'side').read_bytes(),b'side-channel')
            args=json.loads((self.root/'args.json').read_text())
            self.assertEqual(args['args'][:5],['17','unit-user','title with spaces','1','media=Custom.610x200mm'])
            self.assertEqual(args['uri'],'usb://HP/DesignJet%20500%20(C7769B)')
            self.assertEqual(Path(self.lock).read_bytes(),b'')

    def test_cancellation_holds_lock_until_native_child_reaped(self):
        guard=self.root/'guard.json';p=self.launch(cancel=True,guard_file=guard)
        try:
            until=time.monotonic()+4
            while not (self.root/'ready').exists() and time.monotonic()<until:time.sleep(.02)
            self.assertTrue((self.root/'ready').exists())
            with self.assertRaises(BlockingIOError),usb_lock(self.lock):pass
            p.send_signal(signal.SIGTERM);time.sleep(.15)
            with self.assertRaises(BlockingIOError),usb_lock(self.lock):pass
            _,err=p.communicate(timeout=5)
            self.assertEqual(p.returncode,5,err)
            self.assertTrue(guard.exists())
            child=int((self.root/'started').read_text())
            with self.assertRaises(ProcessLookupError):os.kill(child,0)
            with usb_lock(self.lock):pass
        finally:
            if p.poll() is None:p.kill();p.communicate()

    def test_cancel_while_waiting_never_launches_usb_child(self):
        with usb_lock(self.lock):
            p=self.launch()
            try:
                until=time.monotonic()+4
                while not (self.root/'lock-attempt').exists() and time.monotonic()<until:time.sleep(.02)
                self.assertTrue((self.root/'lock-attempt').exists())
                p.send_signal(signal.SIGTERM)
                _,err=p.communicate(timeout=4)
                self.assertEqual(p.returncode,5,err)
                self.assertFalse((self.root/'started').exists())
            finally:
                if p.poll() is None:p.kill();p.communicate()

    def test_lock_survives_abrupt_wrapper_death_until_native_child_exits(self):
        guard=self.root/'guard.json';p=self.launch(cancel=True,guard_file=guard)
        try:
            until=time.monotonic()+4
            while not (self.root/'ready').exists() and time.monotonic()<until:time.sleep(.02)
            self.assertTrue((self.root/'ready').exists())
            p.kill();p.wait(timeout=2)
            with self.assertRaises(BlockingIOError),usb_lock(self.lock):pass
            p.communicate(timeout=4)
            self.assertEqual(p.returncode,-signal.SIGKILL)
            self.assertTrue(guard.exists())
            with usb_lock(self.lock):pass
        finally:
            if p.poll() is None:p.kill();p.communicate()

    def test_reader_clears_device_guard_before_handoff_to_waiting_print(self):
        guard=self.root/'guard.json';p=None
        try:
            with usb_lock(self.lock):
                with DeviceGuard(guard,'read:test') as lease:
                    p=self.launch(guard_file=guard,exit_code=0)
                    until=time.monotonic()+4
                    while not (self.root/'lock-attempt').exists() and time.monotonic()<until:time.sleep(.02)
                    self.assertTrue((self.root/'lock-attempt').exists())
                    self.assertFalse((self.root/'started').exists())
                    lease.clear()
            out,err=p.communicate(b'verified mock print',timeout=5)
            self.assertEqual(p.returncode,0,err);self.assertEqual(out,b'verified mock print')
            self.assertFalse(guard.exists())
        finally:
            if p is not None and p.poll() is None:p.kill();p.communicate()

    def test_failed_print_keeps_guard_and_blocks_another_operation(self):
        guard=self.root/'guard.json';p=self.launch(guard_file=guard,exit_code=7)
        _,err=p.communicate(b'mock bytes',timeout=5);self.assertEqual(p.returncode,7,err)
        self.assertTrue(guard.exists());old=guard.read_bytes();pid=(self.root/'started').read_text()
        with usb_lock(self.lock),self.assertRaises(UnverifiedTransport),DeviceGuard(guard,'read:new'):pass
        p=self.launch(guard_file=guard,exit_code=0);p.communicate(b'never sent',timeout=5)
        self.assertNotEqual(p.returncode,0);self.assertEqual(guard.read_bytes(),old)
        self.assertEqual((self.root/'started').read_text(),pid)


if __name__=='__main__':unittest.main()
