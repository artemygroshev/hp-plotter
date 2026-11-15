"""One fixed final stock A.04.02 recovery preset, servicing all four heads.

No CLI or retry. This is not tube priming with Setup heads. The caller must
hold the shared USB lock and durable guard, verify all RECOVERY_PROOFS and
ADDITIONAL_PROOFS against live code, and check fresh identity and idle state.
Normal IQ dialogue/accounting is bypassed; physical ink delivery is unproved.
"""
from native_recovery import RecoverySession, recovery_payload, parse_recovery_reply
from quiet_end_reads import QuietEndReadSession

ADDITIONAL_PROOFS = (
    ('stock_level2_preset', 0xa023e93c, 164,
     '6e5d22548fefab6c9c95bd963e1bcbd036fcb0a1987a4c65cfd777bc67f4e5ee'),
    ('normal_IQ_level_dispatch', 0xa013eb64, 158,
     'f0d94da2bc3b47aa41205902ebee264a854b4dd2f2bbf6670be5ffc5fef7395e'),
)


def level2_payload(nonce):
    payload = recovery_payload(nonce)
    if payload.count(b'svsOnIntervention_set 0') != 1:
        raise RuntimeError('base payload no longer matches the reviewed stock call')
    return payload.replace(b'svsOnIntervention_set 0', b'svsOnIntervention_set 2')


class StockLevelTwo(RecoverySession, QuietEndReadSession):
    read_identity = QuietEndReadSession.read_identity

    def command_payload(self, kind, nonce, memory=None):
        if kind != 'normal_recovery':
            return super().command_payload(kind, nonce, memory)
        if memory is not None or self.recovery_nonce is not None:
            raise RuntimeError('one stock recovery call only')
        self.recovery_nonce = nonce
        return level2_payload(nonce)

    def validate_reply(self, kind, nonce, raw, memory, report):
        if kind != 'normal_recovery':
            return super().validate_reply(kind, nonce, raw, memory, report)
        proof = parse_recovery_reply(raw, nonce,
                                     closed_by_eoj=self.returned_close_written(report))
        proof['level'] = 2
        report['recovery_reply_proof'] = proof
