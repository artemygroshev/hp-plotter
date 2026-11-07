"""Identity, code and geometry must pass before firmware-specific access."""
import unittest
from designjet_readonly import Client,checked_pointer,bitmap_header,display_metadata,SERIAL
import struct


class ClientChecks(unittest.TestCase):
    def client(self):
        client = object.__new__(Client)
        client.state = {}
        client.checkpoint = lambda:None
        return client

    def test_wrong_serial_and_firmware_fail_identification(self):
        for firmware,serial in (('A.05.01',SERIAL),('A.04.02','another-device')):
            client = self.client()
            client.value = lambda kind,*_:firmware if kind=='fw_info_tagged' else serial
            with self.assertRaises(RuntimeError):
                client.identify()

    def test_mismatched_getter_code_never_calls_a_native_function(self):
        client = self.client()
        client.memory = lambda *_:bytes(96)
        client.value = lambda *_:self.fail('no function call may follow an unmatched code block')
        with self.assertRaises(RuntimeError):
            client.locate()

    def test_signed_pointer_conversion_and_bounded_heap(self):
        self.assertEqual(checked_pointer('-1605104388'),0xa0540cfc)
        for value in ('0','-1','4294967297','268435456','2684370000'):
            with self.assertRaises(ValueError):
                checked_pointer(value)

    def test_wrong_geometry_or_data_pointer_is_not_read(self):
        self.assertEqual(bitmap_header(bytes.fromhex('0000008000000040a0540d08')),0xa0540d08)
        for data in (bytes(12),bytes.fromhex('000000800000004018000000'),bytes(11)):
            with self.assertRaises(ValueError):
                bitmap_header(data)

    def test_blink_phase_layout_and_indices_are_bounded(self):
        raw=struct.pack('>IIIBBI',0xa0540cfc,0xa054111c,2,1,0,1)
        parsed=display_metadata(raw)
        self.assertTrue(parsed['flashing_enabled'])
        self.assertEqual(parsed['sampled_active_index'],1)
        for bad in (raw[:-1],struct.pack('>IIIBBI',0xa0540cfc,0xa054111c,3,1,0,1),
                    struct.pack('>IIIBBI',0xa0540cfc,0xa054111c,2,1,0,2)):
            with self.assertRaises(ValueError):
                display_metadata(bad)


if __name__=='__main__':
    unittest.main(verbosity=2)
