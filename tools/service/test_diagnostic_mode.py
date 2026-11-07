"""The separate diagnostic path preserves framing and final identity checks."""
import contextlib
import base64
import datetime as dt
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import designjet_readonly as client
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'firmware'))
from probe_printer import make_small_read_query, SMALL_READ_COMMANDS


class DiagnosticMode(unittest.TestCase):
    def test_new_commands_are_fixed_reads_with_bounded_fresh_frames(self):
        for kind in client.DIAGNOSTIC_KINDS:
            command = SMALL_READ_COMMANDS[kind]
            self.assertRegex(command,
                rb'^puts R@NONCE@_\[sysODBGet [A-Z0-9-]+(?: [ub])?\]$')
            payload = make_small_read_query(kind,'abcdef',129)
            self.assertEqual(len(payload),129)
            self.assertIn(b'puts Babcdef\n',payload)
            self.assertIn(b'puts Eabcdef\n',payload)
        with self.assertRaises(ValueError):
            make_small_read_query('telemetry_diag_intervention','abcdef',128)
        with self.assertRaises(ValueError):
            make_small_read_query('telemetry_diag_printing;sysODBSet X 1','abcdef',129)

    def test_longest_name_still_rejects_an_old_nonce(self):
        fake=object.__new__(client.Client)
        def reply(nonce):
            return {'nonce':'abcdef','transport':{'received_base64':
                base64.b64encode(('B'+nonce+'\nR'+nonce+'_3\nE'+nonce+'\n').encode()).decode()}}
        with contextlib.redirect_stdout(io.StringIO()):
            fake.query=lambda _:reply('abcdef')
            self.assertEqual(fake.value('telemetry_diag_intervention'),'3')
            fake.query=lambda _:reply('123456')
            with self.assertRaises(ValueError):
                fake.value('telemetry_diag_intervention')

    def test_final_identity_mismatch_never_completes_diagnostics(self):
        class Fake:
            def __init__(self,*args):
                self.state={'complete':False};self.started=0;self.target='fake'
            def identify(self):pass
            def status(self,kinds):self.state['queried']=list(kinds)
            def value(self,kind):return 'different-printer'
            def checkpoint(self):pass
        fake=Fake()
        cutoff=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=1)).isoformat()
        with patch.object(client,'Client',return_value=fake), \
             patch.object(sys,'argv',['reader','diagnostics','--until-utc',cutoff]), \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError,'identity changed'):
                client.main()
        self.assertFalse(fake.state['complete'])
        self.assertEqual(fake.state['queried'],list(client.DIAGNOSTIC_KINDS))


if __name__=='__main__':
    unittest.main()
