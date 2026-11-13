import struct
import unittest
from task_layout_a04 import decode_ids, decode_descriptor


class TaskLayoutChecks(unittest.TestCase):
    def descriptor(self, status=0):
        return struct.pack('>16I', 0xa1801000, 0xa0500000, 245, status, 0,
                           0xa031cb20, 0xa1800800, 0, 0, 0, 0, 0, 0, 0, 0, 0)

    def test_ready_and_suspended_are_distinct_from_pending(self):
        for status, ready, suspended in ((0, True, False), (1, False, True), (2, False, False)):
            with self.subTest(status=status):
                record = decode_descriptor(self.descriptor(status), 0xa1801000)
                self.assertEqual((record['ready'], record['suspended']), (ready, suspended))

    def test_truncation_wrong_task_and_invalid_fields_are_rejected(self):
        for data, tid in ((self.descriptor()[:-1], 0xa1801000),
                          (self.descriptor(), 0xa1802000), (self.descriptor(16), 0xa1801000),
                          (self.descriptor(), 0xa1801001)):
            with self.subTest(tid=tid), self.assertRaises(ValueError):
                decode_descriptor(data, tid)

    def test_capped_duplicate_or_unowned_list_is_rejected(self):
        self.assertEqual(decode_ids(struct.pack('>2I', 0xa1801000, 0xa1802000), 2),
                         (0xa1801000, 0xa1802000))
        for data, count in ((b'', 0), (bytes(256), 64),
                            (struct.pack('>2I', 0xa1801000, 0xa1801000), 2),
                            (struct.pack('>I', 0xa00f1798), 1)):
            with self.subTest(count=count), self.assertRaises(ValueError):
                decode_ids(data, count)


if __name__ == '__main__':
    unittest.main()
