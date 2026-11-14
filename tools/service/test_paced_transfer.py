import unittest

from paced_transfer import transmit


class PacedTransferChecks(unittest.TestCase):
    def test_bytes_order_and_pacing_do_not_depend_on_packet_boundaries(self):
        data = bytes(range(256)) * 5
        output, pauses, records = [], [], []
        def write(chunk):
            output.append(chunk)
            return 0, len(chunk)
        result = transmit(data, write, records.append, pauses.append)
        self.assertEqual(b''.join(output), data)
        self.assertEqual([len(x) for x in output], [257, 257, 257, 257, 252])
        self.assertEqual(pauses, [0.05] * 4)
        self.assertTrue(result['all_bytes_written'])
        self.assertFalse(result['physical_printout_proven'])

    def test_partial_error_or_exception_never_replays_or_sends_a_tail(self):
        for failure in ('partial', 'error', 'exception'):
            with self.subTest(failure=failure):
                calls, records = [], []
                def write(chunk):
                    calls.append(chunk)
                    if len(calls) == 1:
                        return 0, len(chunk)
                    if failure == 'exception':
                        raise OSError('transport lost')
                    return (0, 64) if failure == 'partial' else (-7, 0)
                with self.assertRaises((OSError, RuntimeError)):
                    transmit(bytes(1024), write, records.append, lambda _: None)
                self.assertEqual(len(calls), 2)
                self.assertEqual(records[-1]['offset'], 257)
                self.assertIn(records[-1]['phase'], ('write_result_unknown', 'incomplete_no_retry'))

    def test_bad_input_never_calls_the_transport(self):
        for data in (b'', bytearray(10), 'data'):
            with self.assertRaises(ValueError):
                transmit(data, lambda _: self.fail('unexpected I/O'), lambda _: None)


if __name__ == '__main__':
    unittest.main()
