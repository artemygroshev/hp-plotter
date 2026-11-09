import ctypes as C
import datetime as dt
import hashlib
import re
import struct
import unittest
from unittest.mock import patch

from panel_keys import KEYS, KeySession, key_payload, verified_key, require_compatible_session, parse_key_reply
from test_batch_usb import Fake, Clock


class KeyFake(Fake):
    def bulk_transfer(self, handle, endpoint, data, length, count, timeout):
        if endpoint != 1:
            return super().bulk_transfer(handle, endpoint, data, length, count, timeout)
        raw = C.string_at(data, length)
        if b'fpSimulateKey' not in raw:
            return super().bulk_transfer(handle, endpoint, data, length, count, timeout)
        self.events.append(('out', length)); count._obj.value = length; self.primary += 1
        if self.scenario == 'partial_key':
            count._obj.value = 40
            return -7
        nonce = re.search(rb'puts R([a-f0-9]{6})_', raw)[1]
        if self.scenario == 'old_key':
            nonce = b'ffffff'
        self.pending = (b'Simulating: ENTER\n' if self.scenario == 'native_prefix' else b'')+b'R'+nonce+b'_0\nE'+nonce+b'\n'
        return 0


class PanelKeyTests(unittest.TestCase):
    def test_only_exact_native_prefix_and_fresh_result_are_accepted(self):
        reply = b'Rabcdef_0\nEabcdef\n'
        for raw in (reply, b'Simulating: ENTER\n'+reply):
            self.assertEqual(parse_key_reply(raw, 'abcdef', 'ENTER')['value'], '0')
        for raw in (b'Simulating: TOP\n'+reply,
                    b'Simulating: ENTER\nSimulating: ENTER\n'+reply,
                    b'Simulating: ENTER\nRffffff_0\nEffffff\n',
                    reply+b'trailing data\n', reply.replace(b'_0', b'_1')):
            with self.assertRaises(ValueError):
                parse_key_reply(raw, 'abcdef', 'ENTER')

    def test_old_read_only_dependency_is_rejected_before_hardware_access(self):
        class OldSession:
            def query(self, kind):
                raise ValueError('fixed read commands only')
        require_compatible_session()
        with patch('panel_keys.ReadSession', OldSession), self.assertRaises(RuntimeError):
            require_compatible_session()

    def test_only_empty_class_ID_is_retried_before_any_key(self):
        class EmptyIDs(KeyFake):
            ids = 0
            def control_transfer(self, handle, bm, request, value, index, data, length, timeout):
                if (bm, request) == (0xa1, 0):
                    self.ids += 1
                    if self.ids <= 2:
                        return 0
                return super().control_transfer(handle, bm, request, value, index, data, length, timeout)
        fake = EmptyIDs(); session = self.session(fake)
        with session:
            self.assertEqual(fake.ids, 3)
            self.assertEqual(fake.primary, 0)
        self.assertTrue(session.cleanup_verified)

    def test_empty_ID_has_a_bound_and_negative_error_is_not_retried(self):
        class BrokenID(KeyFake):
            ids = 0
            rc = 0
            def control_transfer(self, handle, bm, request, value, index, data, length, timeout):
                if (bm, request) == (0xa1, 0):
                    self.ids += 1
                    return self.rc
                return super().control_transfer(handle, bm, request, value, index, data, length, timeout)
        for rc, attempts in ((0, 8), (-4, 1)):
            fake = BrokenID(); fake.rc = rc; session = self.session(fake)
            with self.subTest(rc=rc), self.assertRaises(RuntimeError):
                with session:
                    self.fail('must not proceed to input')
            self.assertEqual(fake.ids, attempts)
            self.assertEqual(fake.primary, 0)
            self.assertTrue(session.cleanup_verified)

    def test_no_combinations_or_injected_commands(self):
        for key in KEYS:
            raw = key_payload(key, 'abcdef')
            self.assertEqual(len(raw), 129)
            self.assertEqual(raw.count(b'fpSimulateKey '), 1)
            self.assertIn(('fpSimulateKey '+key+']').encode(), raw)
        for key in ('ALL', 'PAPER', 'CANCEL', 'ENTER TOP', 'ENTER;sysReset', '', None):
            with self.assertRaises(ValueError):
                key_payload(key, 'abcdef')
        with self.assertRaises(ValueError):
            key_payload('ENTER', 'abcdef;exit')

    def session(self, fake):
        return KeySession(5, 2, dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=5),
            key='ENTER', lib=fake, alt_observer=lambda: fake.alt, now=Clock(),
            sleep=lambda _: None, nonce_factory=lambda: 'abcdef', comment_bytes=63)

    def test_fresh_key_ack_and_cleanup(self):
        for scenario in ('ok', 'native_prefix'):
            fake = KeyFake(scenario); session = self.session(fake)
            with session:
                reply = session.query('panel_key')
            self.assertTrue(reply['stream_closed'])
            self.assertTrue(session.cleanup_verified)
            self.assertEqual(fake.primary, 1)
            self.assertEqual(reply['key_reply_proof']['native_prefix_present'], scenario == 'native_prefix')

    def test_partial_write_and_old_reply_never_repeat_key(self):
        for scenario in ('partial_key', 'old_key'):
            fake = KeyFake(scenario); session = self.session(fake)
            with self.subTest(scenario=scenario), self.assertRaises((RuntimeError, ValueError)):
                with session:
                    session.query('panel_key')
            self.assertEqual(fake.primary, 1)
            self.assertFalse(session.stream_closed)
            self.assertTrue(session.cleanup_verified)

    def client(self, *, before=b'screen', busy='0', key_error=False, after_error=False, code=b'code', flashing=False, active=0):
        class Client:
            keys = 0
            def identify(self): pass
            def memory(self, address, length):
                return code if address == 0xa0002000 else struct.pack('>I', 0xa0004000)
            def locate(self): return 1, b'header', 2
            def phases(self):
                return {'pointers':[1,2], 'flashing_enabled':flashing, 'sampled_active_index':active}
            def capture(self, number, *args):
                if number == 'after' and after_error:
                    raise RuntimeError('post-action screen lost')
                return before if number == 'before' else b'changed screen'
            def value(self, kind):
                if kind == 'telemetry_diag_busy': return busy
                self.keys += 1
                if key_error: raise RuntimeError('lost key acknowledgement')
                return '0'
        return Client()

    def attempt(self, client, checkpoints):
        proof = ('fixture', 0xa0002000, 4, hashlib.sha256(b'code').hexdigest())
        with patch('panel_keys.PROOFS', (proof,)):
            return verified_key(client, 'ENTER', hashlib.sha256(b'screen').hexdigest(), checkpoints.append)

    def test_stale_screen_busy_and_changed_code_block_key(self):
        for settings in ({'before': b'another menu'}, {'busy': '1'}, {'code': b'xxxx'},
                         {'flashing':True}, {'active':1}):
            client = self.client(**settings); checkpoints = []
            with self.subTest(settings=settings), self.assertRaises(RuntimeError):
                self.attempt(client, checkpoints)
            self.assertEqual(client.keys, 0)
            self.assertNotIn('key_attempt_started', checkpoints)

    def test_lost_ack_or_readback_is_not_reported_as_success(self):
        for settings in ({'key_error': True}, {'after_error': True}):
            client = self.client(**settings); checkpoints = []
            with self.subTest(settings=settings), self.assertRaises(RuntimeError):
                self.attempt(client, checkpoints)
            self.assertEqual(client.keys, 1)
            self.assertEqual(checkpoints[0], 'key_attempt_started')
            self.assertNotIn('readback_complete', checkpoints)

    def test_one_key_does_not_claim_cleaning_started(self):
        client = self.client(); checkpoints = []
        result = self.attempt(client, checkpoints)
        self.assertEqual(client.keys, 1)
        self.assertEqual(checkpoints[-1], 'readback_complete')
        self.assertFalse(result['cleaning_started'])


if __name__ == '__main__':
    unittest.main()
