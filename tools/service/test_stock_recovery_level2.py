import unittest

from native_recovery import returned_close_payload
from stock_recovery_level2 import StockLevelTwo, level2_payload


class FinalStockRecoveryChecks(unittest.TestCase):
    def session(self):
        session = object.__new__(StockLevelTwo)
        session.recovery_nonce = None
        session.return_clock_scheduled = False
        session.queries = []
        return session

    def test_fixed_frame_replay_and_argument_rejection(self):
        session = self.session()
        with self.assertRaises(RuntimeError):
            session.command_payload('normal_recovery', 'abc123', (0, 4))
        frame = session.command_payload('normal_recovery', 'abc123')
        self.assertEqual(len(frame), 257)
        self.assertEqual(frame.count(b'svsOnIntervention_set 2'), 1)
        self.assertNotIn(b'svsOnIntervention_set 0', frame)
        with self.assertRaises(RuntimeError):
            session.command_payload('normal_recovery', 'def456')
        for nonce in ('abc12', 'ABC123', 'abc123\nexit'):
            with self.assertRaises(ValueError):
                level2_payload(nonce)

    def test_partial_error_and_foreign_returns_fail_closed(self):
        session = self.session()
        for raw in (b'Sabc123\n', b'Sabc123\nRabc123_1\nEabc123\n',
                    b'Sdef456\nRdef456_0\nEdef456\n',
                    b'Sabc123\nRabc123_0\nEabc123\nextra'):
            with self.assertRaises(ValueError):
                session.validate_reply('normal_recovery', 'abc123', raw, None, {'phases': []})
        report = {'phases': []}
        session.validate_reply('normal_recovery', 'abc123',
                               b'Sabc123\nRabc123_0\nEabc123\n', None, report)
        self.assertEqual(report['recovery_reply_proof']['level'], 2)
        self.assertEqual(report['recovery_reply_proof']['head_mask'], 15)
        self.assertFalse(report['recovery_reply_proof']['physical_ink_restoration_proven'])

    def test_no_forward_clock_before_exact_successful_return(self):
        session = self.session()
        session.recovery_nonce = 'abc123'
        for raw in (b'', b'Sabc123\n', b'Sabc123\nRabc123_1\n'):
            self.assertIsNone(session.drain_payload('normal_recovery', raw))
        self.assertEqual(session.drain_payload('normal_recovery', b'Sabc123\nRabc123_0\n'),
                         returned_close_payload())
        self.assertIsNone(session.drain_payload('normal_recovery', b'Sabc123\nRabc123_0\n'))


if __name__ == '__main__':
    unittest.main()
