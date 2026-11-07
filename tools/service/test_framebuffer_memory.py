"""Offline byte ownership, truncation and bitmap-orientation checks."""
import struct
import unittest
from framebuffer_memory import parse_dump, decode_native_bitmap, extract_addressed_reply, extract_tagged_value


def format_dump(address, data):
    rows = []
    for start in range(address & ~15, (address+len(data)+15) & ~15, 16):
        rows.append('%08x:  ' % start + ''.join(
            '%02x ' % data[loc-address] if address <= loc < address+len(data) else '   '
            for loc in range(start, start+16)))
    return ('\n'.join(rows)+'\n').encode()


class MemoryChecks(unittest.TestCase):
    def test_unaligned_partial_rows_preserve_requested_addresses(self):
        data = bytes(range(16))
        self.assertEqual(parse_dump(format_dump(0xa017d468, data), 0xa017d468, 16), data)

    def test_missing_duplicate_extra_and_malformed_rows_fail(self):
        data = format_dump(0xa0001000, bytes(range(32)))
        for bad in (data.splitlines()[0]+b'\n', data+data,
                    format_dump(0xa0001000, bytes(range(33))), data.replace(b'00 ', b'gg ', 1)):
            with self.assertRaises(ValueError):
                parse_dump(bad, 0xa0001000, 32)

    def test_geometry_has_no_padding_or_truncation(self):
        for n in (0, 1023, 1025):
            with self.assertRaises(ValueError):
                decode_native_bitmap(bytes(n))

    def test_independent_corner_pixels_verify_storage_and_orientation(self):
        data = bytearray(1024)
        struct.pack_into('>I', data, 0, 0x80000000)
        struct.pack_into('>I', data, 4*(3*64+63), 1)
        image = decode_native_bitmap(bytes(data))
        self.assertEqual(image.getpixel((0, 0)), (0, 0, 0))
        self.assertEqual(image.getpixel((127, 63)), (0, 0, 0))
        self.assertEqual(image.getpixel((127, 0)), (255, 255, 255))
        self.assertEqual(sum(p == (0, 0, 0) for p in image.getdata()), 2)

    def test_native_reply_uses_end_nonce_and_exact_address_coverage(self):
        body = format_dump(0xa0540cfc, bytes(range(12)))
        for prefix in (b'', b'B0123ab\n'):
            data, report = extract_addressed_reply(prefix+body+b'E0123ab\n', '0123ab', 0xa0540cfc, 12)
            self.assertEqual(data, bytes(range(12)))
            self.assertEqual(report['begin_marker_verified'], bool(prefix))
        for bad in (body+b'Effffff\n', body+b'E0123ab\nX', body+body+b'E0123ab\n',
                    body[:-1]+b'E0123ab\n', b'@PJL COMMENT\n'+body+b'E0123ab\n'):
            with self.assertRaises(ValueError):
                extract_addressed_reply(bad, '0123ab', 0xa0540cfc, 12)

    def test_value_and_nonce_must_be_in_the_same_printed_line(self):
        raw = b'P0123ab -1605104388\nE0123ab\n'
        self.assertEqual(extract_tagged_value(raw,'0123ab'), '-1605104388')
        self.assertEqual(extract_tagged_value(b'B0123ab\n'+raw,'0123ab'), '-1605104388')
        for bad in (raw.replace(b'P0123ab',b'Pffffff'), raw+raw, raw+b'X', b'-1605104388\nE0123ab\n'):
            with self.assertRaises(ValueError):
                extract_tagged_value(bad,'0123ab')

    def test_delayed_old_response_is_not_accepted_as_a_clean_fresh_query(self):
        old=b'B111aaa\nR111aaa_0\nE111aaa\n'
        fresh=b'B222bbb\nF222bbb_A.04.02\nE222bbb\n'
        self.assertEqual(extract_tagged_value(old,'111aaa','R','_'),'0')
        self.assertEqual(extract_tagged_value(fresh,'222bbb','F','_'),'A.04.02')
        with self.assertRaises(ValueError):extract_tagged_value(old+fresh,'222bbb','F','_')


if __name__ == '__main__':
    unittest.main(verbosity=2)
