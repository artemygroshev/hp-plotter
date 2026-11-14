"""One experimental stock A.04.02 recovery at level 1, using all four heads.

No CLI, guard bypass, direct pump/jet parameters or repeat. The caller must
hold the shared lock and durable operation record, verify RECOVERY_PROOFS and
ADDITIONAL_PROOFS against live code, and check fresh identity/idle/ink state.
This extends the earlier level-0 experiment; it is not selective Black cleaning.
"""
from native_recovery import RecoverySession, recovery_payload, parse_recovery_reply
from quiet_end_reads import QuietEndReadSession

ADDITIONAL_PROOFS = (
    ('stock_level1_preset', 0xa023e898, 164,
     'a8ff4cf90fbb89cb8f3c1dce25de01796cf9fd736892bee9dbea2252d6b387f1'),
    ('normal_IQ_level_dispatch', 0xa013eb64, 158,
     'f0d94da2bc3b47aa41205902ebee264a854b4dd2f2bbf6670be5ffc5fef7395e'),
)


def level1_payload(nonce):
    payload = recovery_payload(nonce)
    if payload.count(b'svsOnIntervention_set 0') != 1:
        raise RuntimeError('base payload no longer matches the reviewed stock call')
    return payload.replace(b'svsOnIntervention_set 0', b'svsOnIntervention_set 1')


class StockLevelOne(RecoverySession, QuietEndReadSession):
    read_identity = QuietEndReadSession.read_identity

    def command_payload(self, kind, nonce, memory=None):
        if kind != 'normal_recovery':
            return super().command_payload(kind, nonce, memory)
        if memory is not None or self.recovery_nonce is not None:
            raise RuntimeError('one stock recovery call only')
        self.recovery_nonce = nonce
        return level1_payload(nonce)

    def validate_reply(self, kind, nonce, raw, memory, report):
        if kind != 'normal_recovery':
            return super().validate_reply(kind, nonce, raw, memory, report)
        proof = parse_recovery_reply(raw, nonce,
                                     closed_by_eoj=self.returned_close_written(report))
        proof['level'] = 1
        report['recovery_reply_proof'] = proof
