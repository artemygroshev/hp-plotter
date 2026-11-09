import unittest
from force_true_black import COLOR, ENTER, TRUE_BLACK, UEL, force_true_black


class TrueBlackTests(unittest.TestCase):
    def sample(self):
        return UEL + b'@PJL JOB NAME="test"\n' + COLOR + ENTER + b'\x00\xff\x1b*rC' + UEL + b'@PJL EOJ\n'

    def test_replaces_only_header_and_preserves_binary_raster(self):
        source = self.sample()
        result = force_true_black(source)
        self.assertEqual(result, source.replace(COLOR, TRUE_BLACK, 1))
        self.assertEqual(result.split(ENTER, 1)[1], source.split(ENTER, 1)[1])
        self.assertEqual(len(result), len(source) + 4)

    def test_rejects_ambiguous_or_unreviewed_streams(self):
        source = self.sample()
        bad = [b'', source[1:], source + ENTER,
               source.replace(COLOR, COLOR + COLOR),
               source.replace(COLOR, TRUE_BLACK),
               source.replace(b'@PJL JOB NAME=', b'@PJL COMMENT '),
               source.replace(b'@PJL EOJ', b'@PJL COMMENT'),
               source.replace(ENTER, b'@PJL DEFAULT RENDERMODE=COLOR\n' + ENTER),
               source.replace(ENTER, ENTER + COLOR)]
        for item in bad:
            with self.subTest(item=item[:100]):
                with self.assertRaises(ValueError):
                    force_true_black(item)

    def test_rejects_non_bytes_and_oversized_headers(self):
        with self.assertRaises(ValueError):
            force_true_black('text')
        with self.assertRaises(ValueError):
            force_true_black(self.sample().replace(ENTER, b' ' * 4096 + ENTER))


if __name__ == '__main__':
    unittest.main()
