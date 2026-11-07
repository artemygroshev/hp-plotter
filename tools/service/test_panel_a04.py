"""Offline strict decoding checks; artificial pixels are fixtures, never LCD evidence."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'firmware'))
from decode_panel import decode

HEADER = bytes.fromhex('424d3e010000000000003e000000280000008000000040000000010001000000000000010000d8090000d80900000000000000000000ffffff0000000000')

class PanelA04Checks(unittest.TestCase):
    def test_complete_known_header_requires_explicit_compatibility(self):
        data = b'1086\n'+HEADER+bytes(1024)
        with self.assertRaises(ValueError): decode(data)
        image=decode(data, allow_hp_a04=True)
        self.assertEqual(image.size,(128,64))
        self.assertEqual(image.getpixel((0,0)),(255,255,255))
    def test_no_padding_of_missing_pixels(self):
        for n in (0,1,256,957,1023):
            with self.subTest(n=n), self.assertRaises(ValueError):
                decode(b'1086\n'+HEADER+bytes(n),allow_hp_a04=True)
    def test_two_complete_frames_rejected(self):
        frame=b'1086\n'+HEADER+bytes(1024)
        with self.assertRaises(ValueError): decode(frame*2,allow_hp_a04=True)
    def test_changed_header_rejected(self):
        for i in (18,22,28,30,10):
            data=bytearray(b'1086\n'+HEADER+bytes(1024));data[5+i]^=1
            with self.subTest(i=i),self.assertRaises(ValueError):decode(data,allow_hp_a04=True)
    def test_missing_prefix_rejected(self):
        with self.assertRaises(ValueError): decode(HEADER+bytes(1024),allow_hp_a04=True)
    def test_actual_partial_capture_rejected(self):
        path=Path(__file__).parent/'fixtures/lcd-partial.hex'
        with self.assertRaises(ValueError):decode(bytes.fromhex(path.read_text()),allow_hp_a04=True)
    def test_extra_transport_blocks_cannot_be_silently_ignored(self):
        frame=b'1086\n'+HEADER+bytes(1024)
        for junk in (bytes(64), b' '*64, b'@PJL COMMENT'+b' '*52):
            for damaged in (frame+junk, frame[:900]+junk+frame[900:]):
                with self.subTest(length=len(damaged)), self.assertRaises(ValueError):
                    decode(damaged,allow_hp_a04=True)
    def test_only_known_native_return_line_is_allowed_after_exact_frame(self):
        frame=b'1086\n'+HEADER+bytes(1024)
        self.assertEqual(decode(frame+b'\n1086\n',allow_hp_a04=True).size,(128,64))

if __name__=='__main__':unittest.main()
