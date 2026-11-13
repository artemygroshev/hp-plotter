"""Production gating and allocation lifetime without real USB."""
import base64
import copy
import struct
import unittest

from quiet_ram_session import QuietRamSession
from ram_rollback_probe import frame
from ram_rollback_program import MAGIC
from test_framebuffer_memory import format_dump


class QuietRamChecks(unittest.TestCase):
    def session(self):
        session = object.__new__(QuietRamSession)
        session.workspace = 0xa1800000
        session.plans = {}
        session.queries = []
        session.poisoned = False
        session.stream_closed = True
        session.shadow_accepted = False
        return session

    def evidence(self, session):
        nonce = '111aaa'
        command = ['osFuncCall ' + hex(session.workspace) + ' 1 0']
        session.queries = [{'kind': 'ram_shadow', 'stream_closed': True,
            'nonce': nonce, 'native_results': [7],
            'payload_hex': frame(command, nonce).hex(),
            'received_base64': base64.b64encode(b'B111aaa\n7\nE111aaa\n').decode()}]
        for nonce, offset, data in (
            ('222bbb', 544, struct.pack('>7I', MAGIC, 4, 7,
                                      0x70014e75, 0x70024e75, 0x70014e75, 0)),
            ('333ccc', 512, bytes.fromhex('70014e75'))):
            address = session.workspace + offset
            raw = b'B' + nonce.encode() + b'\n' + format_dump(address, data)
            raw += b'E' + nonce.encode() + b'\n'
            session.queries.append({'kind': 'runtime_mem', 'stream_closed': True,
                'memory': [address, len(data)], 'nonce': nonce,
                'received_base64': base64.b64encode(raw).decode()})

    def test_production_needs_native_receipt_and_later_external_read(self):
        session = self.session()
        with self.assertRaises(ValueError):
            session.schedule('ram_production', ['osFuncCall 0xa1800000 1 1'])
        self.evidence(session)
        session.accept_shadow()
        session.schedule('ram_production', ['osFuncCall 0xa1800000 1 1'])

    def test_missing_reordered_and_corrupted_evidence_is_rejected(self):
        session = self.session()
        self.evidence(session)
        good = copy.deepcopy(session.queries)
        cases = [good[:-1], [good[0], good[2], good[1]]]
        bad = copy.deepcopy(good)
        bad[1]['received_base64'] = bad[2]['received_base64']
        cases.append(bad)
        bad = copy.deepcopy(good)
        bad[0]['received_base64'] = base64.b64encode(b'Bffffff\n7\nEffffff\n').decode()
        cases.append(bad)
        for evidence in cases:
            with self.subTest(evidence=evidence):
                session.queries = evidence
                with self.assertRaises(ValueError):
                    session.accept_shadow()
                self.assertFalse(session.shadow_accepted)

    def test_other_allocation_and_poisoned_session_are_rejected(self):
        session = self.session()
        self.evidence(session)
        session.workspace += 1024
        with self.assertRaises(ValueError):
            session.accept_shadow()
        session.poisoned = True
        with self.assertRaises(RuntimeError):
            session.accept_shadow()

    def test_failed_revalidation_revokes_a_previous_acceptance(self):
        session = self.session()
        self.evidence(session)
        session.accept_shadow()
        session.queries.pop()
        with self.assertRaises(ValueError):
            session.accept_shadow()
        self.assertFalse(session.shadow_accepted)

    def test_acknowledged_free_revokes_allocation_and_production_gate(self):
        session = self.session()
        session.shadow_accepted = True
        session.plans['ram_free'] = ('osMemFree 0xa1800000',)
        report = {}
        session.validate_reply('ram_free', '111aaa', b'B111aaa\n0\nE111aaa\n', None, report)
        self.assertIsNone(session.workspace)
        self.assertFalse(session.shadow_accepted)
        with self.assertRaises(ValueError):
            session.schedule('ram_production', ['osFuncCall 0xa1800000 1 1'])


if __name__ == '__main__':
    unittest.main()
