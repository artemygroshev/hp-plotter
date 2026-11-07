"""Safety and evidence-boundary tests for the BTT one-shot reader; offline."""
import ctypes
from pathlib import Path
import types
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'firmware/status_snapshot.py'
module = types.ModuleType('snapshot_under_test')
exec(compile(SOURCE.read_text(), str(SOURCE), 'exec'), module.__dict__)
text = b'MANUFACTURER:Hewlett-Packard;MODEL:DesignJet 500 (C7769B);'
DEVICE_ID = (len(text)+2).to_bytes(2, 'big') + text


class Function:
    def __init__(self, action):
        self.action = action

    def __call__(self, *args):
        return self.action(*args)


class USB:
    def __init__(self, kernel=1, empty=False, bus=5, release=0):
        self.calls = []
        self.control_requests = []
        self.kernel = kernel
        self.empty = empty
        self.bus = bus
        self.release = release
        actions = {
            'libusb_init': self.init,
            'libusb_exit': lambda *_: None,
            'libusb_open_device_with_vid_pid': lambda *_: 2,
            'libusb_close': lambda *_: None,
            'libusb_get_device': lambda *_: 3,
            'libusb_get_bus_number': lambda *_: self.bus,
            'libusb_get_device_address': lambda *_: 2,
            'libusb_kernel_driver_active': lambda *_: self.kernel,
            'libusb_claim_interface': lambda *_: 0,
            'libusb_release_interface': lambda *_: self.release,
            'libusb_control_transfer': self.control,
        }
        for name, action in actions.items():
            def record(*args, name=name, action=action):
                self.calls.append(name)
                return action(*args)
            setattr(self, name, Function(record))

    def init(self, context):
        context._obj.value = 1
        return 0

    def control(self, handle, direction, request, value, index, buffer, size, timeout):
        self.control_requests.append((direction, request, value, index, size))
        data = (b'' if self.empty else DEVICE_ID) if request == 0 else b'\x18'
        ctypes.memmove(buffer, data, len(data))
        return len(data)


class ReaderTests(unittest.TestCase):
    def adapter(self, kernel=1):
        return {'path': '/recorded/5-1', 'alternate': 1,
                'driver': '/sys/bus/usb/drivers/usblp' if kernel == 1 else None,
                'busnum': '5', 'devnum': '2',
                'descriptor_sha256': module.ADAPTER_DESCRIPTOR_SHA256}

    def run_reader(self, usb, after=None):
        adapter = self.adapter(usb.kernel)
        with patch.object(module.C, 'CDLL', return_value=usb), \
                patch.object(module.ctypes.util, 'find_library', return_value='fake'), \
                patch.object(module, 'adapters', return_value=[after or adapter]):
            return module.read_class_status(adapter)

    def test_bound_driver_retained_with_valid_actual_id(self):
        usb = USB()
        report = self.run_reader(usb)
        self.assertTrue(report['requests']['GET_DEVICE_ID']['decoded']['hp_c7769b_identified'])
        self.assertIn('skipped', report['requests']['GET_PORT_STATUS'])
        self.assertNotIn('libusb_claim_interface', usb.calls)
        self.assertNotIn('libusb_release_interface', usb.calls)
        self.assertEqual(usb.control_requests, [(0xa1, 0, 0, 1, 1024)])
        self.assertTrue(report['cleanup_verified'])

    def test_unbound_reader_releases_ownership(self):
        usb = USB(kernel=0)
        report = self.run_reader(usb)
        self.assertIn('libusb_claim_interface', usb.calls)
        self.assertIn('libusb_release_interface', usb.calls)
        self.assertTrue(report['cleanup_verified'])
        self.assertTrue(all(r[0] == 0xa1 for r in usb.control_requests))
        self.assertTrue(report['requests']['GET_PORT_STATUS']['decoded']['not_error_signal'])

    def test_zero_byte_usb_response_is_invalid(self):
        report = self.run_reader(USB(empty=True))
        self.assertFalse(report['requests']['GET_DEVICE_ID']['decoded']['valid'])
        self.assertEqual(report['requests']['GET_DEVICE_ID']['raw_hex'], '')

    def test_wrong_bus_sends_no_control_requests(self):
        usb = USB(bus=6)
        report = self.run_reader(usb)
        self.assertIn('adapter changed', report['error'])
        self.assertEqual(usb.control_requests, [])

    def test_unknown_kernel_owner_sends_no_control_requests(self):
        usb = USB(kernel=-1)
        report = self.run_reader(usb)
        self.assertEqual(usb.control_requests, [])
        self.assertFalse(report['cleanup_verified'])

    def test_release_failure_is_not_clean(self):
        self.assertFalse(self.run_reader(USB(kernel=0, release=-1))['cleanup_verified'])

    def test_reenumerated_device_is_not_same_cleanup(self):
        after = self.adapter()
        after['devnum'] = '3'
        self.assertFalse(self.run_reader(USB(), after)['cleanup_verified'])

    def test_binding_change_is_not_clean(self):
        after = self.adapter()
        after['driver'] = None
        self.assertFalse(self.run_reader(USB(), after)['cleanup_verified'])

    def test_ownership_detects_char_device_alias_by_device_number(self):
        with tempfile.TemporaryDirectory(prefix='btt-fd-test-', dir='/tmp') as temp:
            root = Path(temp)
            (root/'usb').mkdir()
            (root/'usb'/'002').symlink_to('/dev/null')
            fds = root/'proc'/'1234'/'fd'
            fds.mkdir(parents=True)
            (fds/'9').symlink_to('/dev/null')
            (root/'usbmisc').mkdir()
            mapping = {'/dev/bus/usb/005/002': root/'usb'/'002',
                       '/proc': root/'proc', '/sys/class/usbmisc': root/'usbmisc'}
            with patch.object(module, 'Path', side_effect=lambda value: mapping.get(value, Path(value))):
                report = module.adapter_open_handles([self.adapter()])
            self.assertTrue(report['inspection_complete'])
            self.assertEqual([(o['pid'], o['fd']) for o in report['open_handles']], [(1234, '9')])

    def test_missing_device_makes_ownership_unknown(self):
        with tempfile.TemporaryDirectory(prefix='btt-fd-test-', dir='/tmp') as temp:
            root = Path(temp)
            (root/'proc').mkdir()
            (root/'usbmisc').mkdir()
            mapping = {'/dev/bus/usb/005/002': root/'missing-device',
                       '/proc': root/'proc', '/sys/class/usbmisc': root/'usbmisc'}
            with patch.object(module, 'Path', side_effect=lambda value: mapping.get(value, Path(value))):
                report = module.adapter_open_handles([self.adapter()])
            self.assertFalse(report['inspection_complete'])
            self.assertTrue(report['errors'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
