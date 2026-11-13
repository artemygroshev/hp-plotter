"""Experimental fixed RAM operations with quiet replies and a shadow gate.

No CLI, daemon, guard bypass or automatic retry. The caller owns the USB lock,
durable operation record and allocation. The old execute() stays disabled.
Hardware trials used the same transport mixin and explicit orchestration;
this stricter receipt gate is also checked against their saved replies.
"""
import base64
import struct

from framebuffer_memory import extract_addressed_reply
from quiet_end_reads import QuietEndReadSession
from ram_rollback_probe import RamSession, frame, parse
from ram_rollback_program import MAGIC, checked_workspace


class QuietRamSession(RamSession, QuietEndReadSession):
    def __init__(self, *args, **kwargs):
        if kwargs.get('comment_bytes', 63) != 63:
            raise ValueError('this experiment requires the 63-byte comment profile')
        kwargs['comment_bytes'] = 63
        super().__init__(*args, **kwargs)
        self.shadow_accepted = False

    def schedule(self, kind, commands):
        if kind == 'ram_production' and not self.shadow_accepted:
            raise ValueError('production requires a verified shadow in this allocation')
        return super().schedule(kind, commands)

    def validate_reply(self, kind, nonce, raw, memory, report):
        super().validate_reply(kind, nonce, raw, memory, report)
        if kind == 'ram_free':
            if report['native_results'] != [0]:
                raise RuntimeError('owned allocation free was not acknowledged')
            self.workspace = None
            self.shadow_accepted = False

    def accept_shadow(self):
        """Require the native return, exact receipt and external restored word.

        All three must be strictly closed replies from this same allocation
        and session. This does not clear a guard or start a production call.
        """
        self.shadow_accepted = False
        checked_workspace(self.workspace)
        if self.poisoned or not self.stream_closed:
            raise RuntimeError('uncertain transport cannot authorize another operation')
        calls = [(index, query) for index, query in enumerate(self.queries)
                 if query['kind'] == 'ram_shadow']
        if len(calls) != 1:
            raise ValueError('one shadow call is required')
        index, call = calls[0]
        if not call['stream_closed'] or call.get('native_results') != [7]:
            raise ValueError('shadow native result was not verified')
        command = ['osFuncCall ' + hex(self.workspace) + ' 1 0']
        if (bytes.fromhex(call['payload_hex']) != frame(command, call['nonce'])
                or parse(base64.b64decode(call['received_base64']), call['nonce'], 1) != [7]):
            raise ValueError('shadow call bytes or fresh native reply differ')
        expected = (MAGIC, 4, 7, 0x70014e75, 0x70024e75, 0x70014e75, 0)
        receipt_seen = False
        restored_seen = False
        for query in self.queries[index + 1:]:
            if query['kind'] != 'runtime_mem' or not query['stream_closed']:
                continue
            address, length = query['memory']
            if (address, length) not in ((self.workspace + 544, 28),
                                         (self.workspace + 512, 4)):
                continue
            data, _ = extract_addressed_reply(
                base64.b64decode(query['received_base64']), query['nonce'], address, length)
            if address == self.workspace + 544:
                if struct.unpack('>7I', data) != expected:
                    raise ValueError('shadow receipt differs')
                receipt_seen = True
            elif receipt_seen:
                if data != bytes.fromhex('70014e75'):
                    raise ValueError('external restored word differs')
                restored_seen = True
        if not receipt_seen or not restored_seen:
            raise ValueError('receipt and later external restored-word read are required')
        self.shadow_accepted = True
