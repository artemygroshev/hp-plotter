import unittest
from unittest.mock import patch

import setup_probe
from setup_probe import CASES, ProbeSession, parse_reply, payload, setup_gate_model


class SetupProbeTests(unittest.TestCase):
    def test_only_fixed_pure_calls_fit_transport(self):
        for kind, (argument, expected) in CASES.items():
            frame = payload(kind, '123abc')
            self.assertEqual(len(frame), 129)
            self.assertEqual(frame.count(b'osFuncCall '), 1)
            self.assertIn(f'osFuncCall 0xa00a1058 1 {argument}\n'.encode(), frame)
            self.assertEqual(parse_reply(kind, '123abc',
                             f'B123abc\n{expected}\n\nE123abc\n'.encode())['native_result'], expected)
        for kind, nonce in [('osFuncCall', '123abc'), ('setup_lookup_3', 'x;exit')]:
            with self.assertRaises(ValueError):
                payload(kind, nonce)

    def test_code_proof_and_no_replay_are_required(self):
        session = object.__new__(ProbeSession)
        session.queries = []
        with self.assertRaises(RuntimeError):
            session.command_payload('setup_lookup_3', '123abc')
        session.proofs_verified = True
        session.command_payload('setup_lookup_3', '123abc')
        session.queries.append({'kind': 'setup_lookup_3'})
        with self.assertRaises(RuntimeError):
            session.command_payload('setup_lookup_3', 'abcdef')
        with self.assertRaises(RuntimeError):
            session.command_payload('setup_lookup_0', 'abcdef', (0, 4))

    def test_legacy_transport_is_rejected_before_opening_usb(self):
        with patch.object(setup_probe.ReadSession, 'query', lambda *args: None), \
                patch.object(setup_probe.batch_read, 'collect') as collector:
            with self.assertRaisesRegex(RuntimeError, 'matching batch_usb'):
                setup_probe.collect(None)
            collector.assert_not_called()

    def test_bad_native_replies_are_not_accepted(self):
        for reply in (b'B123abc\n0\nE123abc\n', b'B123abc\n1\n',
                      b'Babcdef\n1\nEabcdef\n', b'noise\nB123abc\n1\nE123abc\n',
                      b'B123abc\n1\nE123abc\nextra',
                      b'B123abc\n1\nE123abc\nB123abc\n1\nE123abc\n'):
            with self.assertRaises(ValueError):
                parse_reply('setup_lookup_3', '123abc', reply)

    def test_four_missing_heads_differ_from_one_missing(self):
        self.assertTrue(setup_gate_model([1, 1, 1, 1])['all_heads_missing_bit'])
        self.assertFalse(setup_gate_model([1, 2, 2, 2])['all_heads_missing_bit'])
        self.assertFalse(setup_gate_model([0x0100000a, 2, 2, 2])['all_heads_missing_bit'])
        self.assertFalse(setup_gate_model([1, 1, 1, 1])['priming_authorized_by_model'])
        for masks in ([1, 1, 1], [1, 1, 1, -1], [True, 1, 1, 1]):
            with self.assertRaises(ValueError):
                setup_gate_model(masks)


if __name__ == '__main__':
    unittest.main()
