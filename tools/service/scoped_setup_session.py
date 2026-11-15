"""Bounded transport for the fixed 832-byte scoped Setup experiment.

No CLI or guard bypass. Caller owns identity/code proofs, allocation, lock,
durable pending record, result/receipt/read-back, cleanup and explicit free.
The legacy 576-byte RAM transport retains its original bounds.
"""
import re

from quiet_end_reads import QuietEndReadSession
from ram_rollback_probe import RamSession, fixed_call
from ram_rollback_program import checked_workspace, CACHE_CLEAR
from setup_scoped_roundtrip import build
from tick_guarded_native import frame as guarded_frame, SUPPRESSED


class ScopedSetupSession(RamSession, QuietEndReadSession):
    floor = None
    construction_verified = False
    cache_verified = False

    def schedule(self, kind, commands):
        if kind in self.plans or not kind.startswith('ram_'):
            raise ValueError('one fixed unique RAM operation only')
        if kind.startswith('ram_load_'):
            checked_workspace(self.workspace)
            if not 1 <= len(commands) <= 4:
                raise ValueError('one to four bounded copies per frame')
            for command in commands:
                match = re.fullmatch(r'osFuncCall 0xa0010770 3 (0x[a-f0-9]+) (0x[a-f0-9]+) (0x[a-f0-9]+)', command)
                if not match:
                    raise ValueError('only immutable-to-owned copies allowed')
                source, target, length = (int(x, 16) for x in match.groups())
                if (not 1 <= length <= 64 or not 0xa0001000 <= source <= 0xa0380000 - length
                        or not self.workspace <= target <= self.workspace + 832 - length):
                    raise ValueError('copy leaves the fixed 832-byte construction')
            self.construction_verified = self.cache_verified = False
        elif kind == 'ram_program_cache_clear':
            if not self.construction_verified or commands != [fixed_call(CACHE_CLEAR, 0, self.workspace, 832)]:
                raise ValueError('cache requires the verified fixed construction')
        elif kind == 'ram_scoped':
            if (not self.construction_verified or not self.cache_verified
                    or commands != ['osFuncCall ' + hex(self.workspace) + ' 0']):
                raise ValueError('execution requires exact construction and acknowledged cache clear')
        elif kind in ('ram_shadow', 'ram_production'):
            raise ValueError('legacy execution modes are not allowed in this experiment')
        else:
            return super().schedule(kind, commands)
        self.plans[kind] = tuple(commands)

    def accept_construction(self, observed):
        self.construction_verified = self.cache_verified = False
        checked_workspace(self.workspace)
        if self.poisoned or not self.stream_closed or observed != build(self.workspace)['blob']:
            raise ValueError('complete closed read-back must match all fixed 832 bytes')
        self.construction_verified = True

    def command_payload(self, kind, nonce, memory=None):
        payload = super().command_payload(kind, nonce, memory)
        if kind in self.plans:
            if self.floor is None:
                raise RuntimeError('fresh HP tick floor required for each native job')
            return guarded_frame(self.plans[kind], nonce, self.floor)
        return payload

    def validate_reply(self, kind, nonce, raw, memory, report):
        super().validate_reply(kind, nonce, raw, memory, report)
        if kind not in self.plans:
            return
        if SUPPRESSED in report['native_results']:
            raise RuntimeError('HP tick guard suppressed a possibly stale native job')
        if kind == 'ram_program_cache_clear':
            if report['native_results'] != [0]:
                raise RuntimeError('construction cache clear not acknowledged')
            self.cache_verified = True
        if kind == 'ram_free':
            if report['native_results'] != [0]:
                raise RuntimeError('owned allocation free not acknowledged')
            self.workspace = None
            self.construction_verified = self.cache_verified = False
