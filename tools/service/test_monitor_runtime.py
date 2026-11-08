"""Offline concurrency, cancellation, byte preservation and stale-cache tests."""
import datetime as dt
import io
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from urllib.request import urlopen,Request
from urllib.error import HTTPError
from http.server import ThreadingHTTPServer
from PIL import Image
from access_lock import usb_lock
from framebuffer_memory import native_png,decode_native_bitmap
from monitor import unsafe_new_capture,public_snapshot,cycle_window
from status_server import current_status,handler
from transaction_outcome import safely_closed
from trace_sequential_echo import idle_adapter,PreflightError

SERVICE=Path(__file__).resolve().parent


class RuntimeChecks(unittest.TestCase):
    def test_complete_cycle_start_window_is_explicit_and_bounded(self):
        self.assertEqual(cycle_window({}),90)
        self.assertEqual(cycle_window({'minimum_cycle_window_seconds':900}),900)
        for value in (True,89,7201,'900'):
            with self.assertRaises(ValueError):cycle_window({'minimum_cycle_window_seconds':value})

    def test_idle_binding_must_match_the_explicit_policy_and_descriptor(self):
        row={'descriptor_sha256':'expected','driver':None,'alternate':0}
        support={'ADAPTER_DESCRIPTOR_SHA256':'expected'}
        with self.assertRaises(PreflightError):idle_adapter([row],support)
        support.update(IDLE_DRIVER=None,IDLE_ALTERNATE=0)
        self.assertIs(idle_adapter([row],support),row)
        for bad in (dict(row,alternate=1),dict(row,descriptor_sha256='other'),
                    dict(row,driver='/sys/bus/usb/drivers/usblp')):
            with self.assertRaises(PreflightError):idle_adapter([bad],support)

    def test_public_png_is_verified_and_private_identity_is_never_published(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);view=root/'view';view.mkdir()
            raw=bytes(1024);binary=root/'lcd.bin';binary.write_bytes(raw)
            png=root/'lcd.png';png.write_bytes(native_png(raw))
            state={'identity':{'engine_firmware':'A.04.02','model':'test-model','serial':'PRIVATE-SERIAL'},
                'status':{'media':{'raw':'Plain Paper'},'serial':{'raw':'PRIVATE-SERIAL'}},
                'screens':[{'phase_index':0,'began_utc':'test','ended_utc':'test',
                    'sha256':hashlib.sha256(raw).hexdigest(),'binary':str(binary),'png':str(png)}],
                'complete':False}
            public=public_snapshot(SimpleNamespace(state=state),view)
            self.assertFalse(public['complete'])
            self.assertNotIn('PRIVATE-SERIAL',json.dumps(public))
            self.assertEqual((view/public['screens'][0]['file']).read_bytes(),png.read_bytes())
            state['status']['diag_intervention']={'raw':'1','available':True}
            extended=public_snapshot(SimpleNamespace(state=state),view,include_diagnostics=True)
            self.assertEqual(extended['fields_expected'],44)
            self.assertEqual(extended['fields']['diag_intervention']['raw'],'1')
            self.assertNotIn('PRIVATE-SERIAL',json.dumps(extended))
            png.write_bytes(native_png(bytes([255])*1024))
            with self.assertRaises(ValueError):public_snapshot(SimpleNamespace(state=state),view)

    def test_prewrite_failure_can_recover_but_partial_out_cannot(self):
        report={'cleanup':{'verified':True},'transport':{'cleanup_verified':True,
            'write_attempts':0,'written_bytes':0,'write_completed':False}}
        self.assertTrue(safely_closed(report))
        report['transport']['write_attempts']=1
        for count in (0,32,128):
            report['transport']['written_bytes']=count
            self.assertFalse(safely_closed(report))
        report['transport'].update(write_completed=True,small_stopped_after_end_and_two_quiet_phases=True)
        self.assertTrue(safely_closed(report))
        report['cleanup']['verified']=False
        self.assertFalse(safely_closed(report))

    def test_png_matches_independent_decoder_including_scale_and_orientation(self):
        data=bytes((i*37+11)%256 for i in range(1024))
        expected=decode_native_bitmap(data)
        for scale in (1,8):
            image=Image.open(io.BytesIO(native_png(data,scale))).convert('RGB')
            self.assertEqual(image.tobytes(),expected.resize((128*scale,64*scale),resample=0).tobytes())
        for bad in (bytes(1023),bytes(1025)):
            with self.assertRaises(ValueError):native_png(bad)

    def test_lock_refuses_symlink_and_permissive_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder);target=path/'target';target.write_text('')
            (path/'link').symlink_to(target)
            with self.assertRaises(OSError),usb_lock(str(path/'link')):pass
            target.chmod(0o644)
            with self.assertRaises(RuntimeError),usb_lock(str(target)):pass

    def test_lock_is_shared_between_independent_processes(self):
        with tempfile.TemporaryDirectory() as folder:
            lock=folder+'/usb.lock'
            command=[sys.executable,'-c',
                'import sys;sys.path.insert(0,sys.argv[1]);from access_lock import usb_lock;'
                'c=usb_lock(sys.argv[2]);c.__enter__()',str(SERVICE),lock]
            with usb_lock(lock):
                p=subprocess.run(command,capture_output=True)
                self.assertNotEqual(p.returncode,0)
                self.assertIn(b'BlockingIOError',p.stderr)
            self.assertEqual(subprocess.run(command,capture_output=True).returncode,0)

    def test_missing_reply_and_uncertain_cleanup_latch_monitor(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'transaction-unverified.json').write_text('{}')
            self.assertTrue(unsafe_new_capture(root,0))
            (root/'transaction-unverified.json').unlink()
            day=root/'panel-live-TEST';day.mkdir()
            report=day/'read-test.json'
            report.write_text(json.dumps({'no_usb_started':True,'error':'queue busy'}))
            self.assertFalse(unsafe_new_capture(root,0))
            report.write_text(json.dumps({'transport':{},'cleanup':{'verified':False}}))
            self.assertTrue(unsafe_new_capture(root,0))

    def test_http_exposes_only_sanitized_cache_and_marks_old_data(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            old=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(hours=2)).isoformat()
            (root/'status.json').write_text(json.dumps({'state':'waiting','last_success_utc':old,'latest':None}))
            self.assertTrue(current_status(root)['stale'])
            server=ThreadingHTTPServer(('127.0.0.1',0),handler(root))
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            base='http://127.0.0.1:'+str(server.server_port)
            try:
                with urlopen(base+'/api/status') as response:
                    self.assertTrue(json.load(response)['stale'])
                for path in ('/../config.json','/screen/../../config.json','/api/print'):
                    with self.assertRaises(HTTPError) as error:urlopen(base+path)
                    self.assertEqual(error.exception.code,404)
                with self.assertRaises(HTTPError) as error:urlopen(Request(base+'/api/status',data=b'{}'))
                self.assertEqual(error.exception.code,501)
            finally:server.shutdown();server.server_close();thread.join()


if __name__=='__main__':unittest.main()
