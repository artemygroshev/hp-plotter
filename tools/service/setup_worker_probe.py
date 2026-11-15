"""Audit framing for the unverified complete A04 Setup-head check.

The standalone live path is disabled after a hardware attempt returned only
its initial marker. The frame remains available for auditing that attempt.
This is a servicing operation: the stock worker sends mechanical message 0x54
and updates head accounting. It is not a pure read. It does not start the IDS
installation FSM or the tube-purging worker. Callers must check current device,
code, idle context, lock, durable guard, outcome and transport cleanup.
"""
import re

from quiet_end_reads import QuietEndReadSession
from tick_guarded_native import frame, SUPPRESSED


KIND = 'setup_worker_stock_check'
COMMAND = 'osFuncCall 0xa00f1710 1 0'


def audit_payload(nonce, minimum_ticks):
    """Pure encoding for the historical attempt, never a live executor."""
    return frame([COMMAND], nonce, minimum_ticks)


class SetupWorkerSession(QuietEndReadSession):
    def command_payload(self, kind, nonce, memory=None):
        if kind != KIND:
            return super().command_payload(kind, nonce, memory)
        raise RuntimeError('standalone worker completion unverified; live invocation disabled here')

    def phase_limit(self, kind):
        return 20 if kind == KIND else super().phase_limit(kind)

    def validate_reply(self, kind, nonce, raw, memory, report):
        if kind != KIND:
            return super().validate_reply(kind, nonce, raw, memory, report)
        if not re.fullmatch('[a-f0-9]{6}', nonce):
            raise ValueError('fresh nonce required')
        match = re.fullmatch(rb'B' + nonce.encode() + rb'\n(-?[0-9]+)\nE'
                             + nonce.encode() + rb'\n', raw)
        if not match:
            raise ValueError('worker result is not completely and freshly framed')
        value = int(match[1])
        if value == SUPPRESSED:
            raise RuntimeError('HP tick floor suppressed the worker call')
        if value not in (0, 1):
            raise ValueError('unexpected Setup-head worker result')
        report['setup_worker_result'] = value
