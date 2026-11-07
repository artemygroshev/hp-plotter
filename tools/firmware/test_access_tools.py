"""Failure-path checks using an emulated libusb; never opens real USB hardware."""
from io import BytesIO
import os
import json
from pathlib import Path
import unittest
import threading
import time
from PIL import Image
import probe_printer as probe
import decode_panel
import inspect_firmware
import panel_query


class Function:
    def __init__(self, callback): self.callback = callback
    def __call__(self, *args): return self.callback(*args)


class FakeUSB:
    def __init__(self, scenario='ok', kernel=1):
        self.scenario = scenario; self.kernel = kernel; self.original_kernel = kernel
        self.alt = 0; self.auto = False; self.out = []; self.closed = False
        self.exited = False; self.released = 0; self.answered = False
        self.restores = 0
        self.prequery_answered = False
        for name in ('init', 'exit', 'open_device_with_vid_pid', 'close', 'get_device',
                     'get_bus_number', 'get_device_address', 'set_auto_detach_kernel_driver',
                     'kernel_driver_active', 'claim_interface', 'release_interface',
                     'set_interface_alt_setting', 'control_transfer', 'bulk_transfer'):
            setattr(self, 'libusb_'+name, Function(getattr(self, name)))
    def init(self, ctx): ctx._obj.value = 1; return 0
    def exit(self, ctx): self.exited = True
    def open_device_with_vid_pid(self, *args): return 10
    def close(self, handle): self.closed = True
    def get_device(self, handle): return 20
    def get_bus_number(self, dev): return 6
    def get_device_address(self, dev): return 2
    def set_auto_detach_kernel_driver(self, *args): self.auto = True; return 0
    def kernel_driver_active(self, *args): return self.kernel
    def claim_interface(self, *args):
        if self.auto: self.kernel = 0
        return 0
    def release_interface(self, *args):
        self.released += 1
        if self.scenario == 'release_failure': return -6
        self.kernel = self.original_kernel; return 0
    def set_interface_alt_setting(self, handle, interface, value):
        if value == 0:
            self.restores += 1
            if self.scenario == 'restore_exception': raise RuntimeError('simulated restore exception')
            if self.scenario == 'restore_failure': return -9
        self.alt = value
        if value == 1 and self.scenario == 'select_partial_failure': return -9
        return 0
    def control_transfer(self, handle, bm, req, value, index, data, length, timeout):
        data._obj.value = self.alt; return 1
    def bulk_transfer(self, handle, endpoint, data, length, count, timeout):
        import ctypes as C
        count._obj.value = 0
        if endpoint == 1:
            self.out.append(C.string_at(data, length))
            if self.scenario == 'partial_write': count._obj.value = 8; return -7
            count._obj.value = length; return 0
        if not self.out:
            if self.scenario == 'delayed_reply' and not self.prequery_answered:
                self.prequery_answered = True
                raw = b'@PJL ECHO BTT_previous123\r\n\f'
                C.memmove(data, raw, len(raw)); count._obj.value = len(raw)
                return 0
            return -9 if self.scenario == 'reverse_stall' else -7
        if not self.answered:
            self.answered = True
            raw = self.out[0] if self.scenario == 'loopback' else b'@PJL ECHO BTT_0123456789abcdef\r\n\f'
            C.memmove(data, raw, len(raw)); count._obj.value = len(raw)
            return 0
        return -7


class Clock:
    def __init__(self): self.value = 0
    def __call__(self): self.value += .1; return self.value


class AccessChecks(unittest.TestCase):
    nonce = '0123456789abcdef'
    def execute_fake(self, scenario='ok', kernel=1):
        fake = FakeUSB(scenario, kernel)
        result = probe.transact(probe.make_query('echo', self.nonce), 6, 2, lib=fake, now=Clock())
        self.assertTrue(fake.closed and fake.exited)
        self.assertEqual(fake.released, 1)
        return fake, result
    def test_framed_echo(self):
        f, r = self.execute_fake()
        self.assertTrue(r['cleanup_verified'] and r['write_completed'])
        self.assertEqual(len(f.out), 1)
        self.assertTrue(probe.classify_echo(r['received_text'].encode(), self.nonce, f.out[0])['pjl_echo_frame_valid'])
    def test_input_loopback_is_not_reply(self):
        f, r = self.execute_fake('loopback')
        checked = probe.classify_echo(r['received_text'].encode(), self.nonce, f.out[0])
        self.assertFalse(checked['pjl_echo_frame_valid'])
        self.assertTrue(checked['input_loopback_suspected'])
    def test_unframed_or_wrong_nonce_rejected(self):
        payload = probe.make_query('echo', self.nonce)
        for raw in (b'@PJL ECHO BTT_0123456789abcdef\r\n',
                    b'@PJL ECHO BTT_ffffffffffffffff\r\n\f', b'junk'):
            self.assertFalse(probe.classify_echo(raw, self.nonce, payload)['pjl_echo_frame_valid'])
    def test_stall_stops_before_output(self):
        f, r = self.execute_fake('reverse_stall')
        self.assertEqual(f.out, [])
        self.assertEqual(r['write_attempts'], 0)
        self.assertTrue(r['cleanup_verified'])
    def test_partial_write_is_not_replayed(self):
        f, r = self.execute_fake('partial_write')
        self.assertEqual(len(f.out), 1)
        self.assertEqual(r['written_bytes'], 8)
        self.assertFalse(r['write_completed'])
        self.assertTrue(r['cleanup_verified'])
    def test_partial_alt_selection_is_restored(self):
        f, r = self.execute_fake('select_partial_failure')
        self.assertEqual(f.out, [])
        self.assertEqual(f.alt, 0)
        self.assertTrue(r['cleanup_verified'])
    def test_restore_failure_is_not_accepted(self):
        f, r = self.execute_fake('restore_failure')
        self.assertFalse(r['cleanup_verified'])
        self.assertFalse(r['cleanup']['alt_verified'])
    def test_restore_exception_does_not_skip_release(self):
        f, r = self.execute_fake('restore_exception')
        self.assertFalse(r['cleanup_verified'])
        self.assertIn('restore_error', r['cleanup'])
    def test_release_failure_is_not_accepted(self):
        f, r = self.execute_fake('release_failure')
        self.assertFalse(r['cleanup_verified'])
    def test_unbound_kernel_driver_stays_unbound(self):
        f, r = self.execute_fake(kernel=0)
        self.assertFalse(f.auto)
        self.assertTrue(r['cleanup_verified'])
        self.assertEqual(f.kernel, 0)

    def test_stale_device_alt_uses_independent_host_observation(self):
        fake = FakeUSB(kernel=0)
        def stale_control(handle, bm, req, value, index, data, length, timeout):
            data._obj.value = 0
            return 1
        fake.libusb_control_transfer = Function(stale_control)
        r = probe.transact(probe.make_query('echo', self.nonce), 6, 2,
                           lib=fake, now=Clock(), alt_observer=lambda: fake.alt)
        self.assertTrue(r['selected_alt_report']['device_host_disagreement'])
        self.assertEqual(r['selected_alt_report']['host_sysfs'], 1)
        self.assertTrue(r['write_completed'])
        self.assertTrue(r['cleanup_verified'])
        self.assertEqual(fake.alt, 0)

    def test_delayed_reply_is_preserved_separately(self):
        import base64
        fake, r = self.execute_fake('delayed_reply')
        self.assertEqual(base64.b64decode(r['prequery_received_base64']),
                         b'@PJL ECHO BTT_previous123\r\n\f')
        self.assertNotIn('previous123', r['received_text'])
        self.assertTrue(r['cleanup_verified'])

    def test_reverse_read_unblocks_pending_forward_write(self):
        class BlockingBridge(FakeUSB):
            def __init__(self):
                super().__init__(kernel=0)
                self.reply_drained=threading.Event()
            def bulk_transfer(self, handle, endpoint, data, length, count, timeout):
                if self.closed: raise RuntimeError('transfer after close')
                if endpoint==1:
                    import ctypes as C
                    self.out.append(C.string_at(data,length))
                    count._obj.value=length if self.reply_drained.wait(.7) else 0
                    return 0 if count._obj.value==length else -7
                rc=super().bulk_transfer(handle,endpoint,data,length,count,timeout)
                if count._obj.value: self.reply_drained.set()
                elif self.out: time.sleep(.005)
                return rc
        fake=BlockingBridge()
        r=probe.transact(probe.make_query('echo',self.nonce),6,2,lib=fake,
                         concurrent_read=True,read_seconds=1)
        self.assertTrue(r['write_completed'])
        self.assertTrue(r['cleanup_verified'])
        self.assertIn(self.nonce,r['received_text'])
        self.assertTrue(fake.closed)

    def test_panel_markers_reject_loopback_and_wrong_nonce(self):
        payload,script=panel_query.make_query(self.nonce)
        for raw in (payload,b'BTT_LCD_BEGIN_wrong\nBMdata\nBTT_LCD_END_wrong\n'):
            with self.assertRaises(ValueError): panel_query.frame_body(raw,self.nonce)
        raw=('BTT_LCD_BEGIN_'+self.nonce+'\n1086\nBMdata\nBTT_LCD_END_'+self.nonce+'\n').encode()
        self.assertEqual(panel_query.frame_body(raw,self.nonce),b'1086\nBMdata\n')

    def test_get_device_id_can_precede_query_without_forward_replay(self):
        class NeedsIdentityRead(FakeUSB):
            def __init__(self): super().__init__(); self.primed=False
            def control_transfer(self,handle,bm,req,value,index,data,length,timeout):
                if (bm,req,value,index)==(0xa1,0,0,1):
                    self.primed=True
                    return 0
                return super().control_transfer(handle,bm,req,value,index,data,length,timeout)
            def bulk_transfer(self,handle,endpoint,data,length,count,timeout):
                if endpoint==1 and not self.primed:
                    count._obj.value=0
                    return -7
                return super().bulk_transfer(handle,endpoint,data,length,count,timeout)
        fake=NeedsIdentityRead()
        r=probe.transact(probe.make_query('echo',self.nonce),6,2,lib=fake,
                         now=Clock(),prime_device_id=True)
        self.assertTrue(r['write_completed'])
        self.assertEqual(r['device_id_before_query']['rc'],0)
        self.assertEqual(len(fake.out),1)
        self.assertTrue(r['cleanup_verified'])
    def test_descriptors_and_bad_lengths(self):
        good = bytes([9,4,0,1,2,7,1,2,0,7,5,1,2,64,0,0,7,5,0x82,2,64,0,0])
        probe.validate_descriptors(good)
        for bad in (good[:-1], good.replace(bytes([0x82,2]), bytes([0x83,2])), bytes([0,4])):
            with self.assertRaises(ValueError): probe.validate_descriptors(bad)
    def test_ascii_nonce_only(self):
        for bad in ('а'*16, 'a\n@PJL SET X=1', 'short'):
            with self.assertRaises(ValueError): probe.make_query('echo', bad)
    def test_container_checksum_vectors(self):
        for raw, expected in [(b'',0),(b'\xff\xff\x00\x01',1),(b'\x01',256),
                              (b'\x01\x02\x03',1026)]:
            self.assertEqual(inspect_firmware.checksum(raw),expected)
    def test_both_official_releases_register_commands(self):
        root = Path(os.environ.get('HP_PLOTTER_FIXTURES',Path(__file__).resolve().parent))
        if not all((root/('DJ500_A.'+v+'.fmw')).is_file() for v in ('04.02','05.01')):
            self.skipTest('proprietary firmware fixtures must be obtained separately from HP')
        for version in ['04.02','05.01']:
            evidence = inspect_firmware.inspect(root/('DJ500_A.'+version+'.fmw'))
            self.assertTrue(evidence['container_checksum_valid'])
            targets = set()
            for name, registrations in evidence['commands'].items():
                self.assertEqual(len(registrations),1,name)
                self.assertTrue(registrations[0]['registration_pattern'],name)
                targets.add(registrations[0]['registration_call_target'])
            self.assertEqual(len(targets),1)
    def bitmap(self, fmt):
        im = Image.new('1', (128,64));im.putdata([(x//8+y//8)%2 for y in range(64) for x in range(128)])
        buf = BytesIO();im.save(buf, format=fmt)
        return im, buf.getvalue()
    def test_bmp_false_prefix_and_exact_pixels(self):
        image, blob = self.bitmap('BMP')
        got = decode_panel.decode(b'log: BM not a bitmap\n'+blob+b'\n0\n')
        self.assertEqual(got.tobytes(), image.convert('RGB').tobytes())
    def test_xbm_exact_pixels(self):
        image, blob = self.bitmap('XBM')
        self.assertEqual(decode_panel.decode(blob).tobytes(), image.convert('RGB').tobytes())
    def test_ambiguous_and_truncated_images_rejected(self):
        _, blob = self.bitmap('BMP')
        for data in (blob+blob, blob[:-1], b'garbage', b'x'*65537):
            with self.assertRaises((ValueError, OSError)): decode_panel.decode(data)


if __name__ == '__main__':
    unittest.main(verbosity=2)
