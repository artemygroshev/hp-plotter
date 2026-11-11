"""Read-only A.04.02 investigation of the Setup-head recognition gate.

This runs three fixed calls to a pure ROM lookup, after checking the live
wrapper, trampoline, function and table. It does not emulate a head, write
memory, enter priming, or call the recognition/servicing routines themselves.
No caller-supplied native address or argument is accepted.
"""
import argparse
import datetime as dt
import hashlib
import re
import struct

import batch_read
from batch_usb import ReadSession
import probe_printer as probe


PROOFS = (
    ('osFuncCall_wrapper', 0xa0261f2c, 460,
     'db5f8614bc58ffa3fff8d3ab0420f041f4f677893efe6c2a7626bdb20ae520d7'),
    ('native_trampoline', 0xa028e9d0, 222,
     'aa577af7d5f98b2c78dc6aebc10ff41574c68113ef0ae9749e8996e1c786c563'),
    ('context_getter', 0xa0350fbc, 14,
     '9bdcd9ca9c91cc870a15433e4635e1ffd9f3891745368a69f5687de30aa881bc'),
    ('pure_status_to_mask', 0xa00a1058, 44,
     'ae80003d47db99f08477dda1e2ae2518b23cb41ed0912c825296839deab84c60'),
    ('lookup_table', 0xa00a7288, 58,
     '27ee2b239f8ae606c0ed46f48c81b7d095c22774600ab2d41362d46b627edd95'),
    ('decimal_result_format', 0xa02626c8, 4,
     'cb3ae3b5b3b5195ab842abdd24444d3a6d33cf21d7fe0d3e9301997c4b3bd533'),
)
CASES = {'setup_lookup_0': (0, 2), 'setup_lookup_3': (3, 1),
         'setup_lookup_29': (29, 2048)}


def payload(kind, nonce):
    if kind not in CASES or not re.fullmatch(r'[a-f0-9]{6}', nonce):
        raise ValueError('require a fixed lookup case and a fresh nonce')
    argument, _ = CASES[kind]
    # The format is %ld, but the HP output channel adds a newline (verified
    # live). The following empty puts adds one more; accept that exact framing.
    script = (f'puts B{nonce}\nosFuncCall 0xa00a1058 1 {argument}\n'
              f'puts {{}}\nputs E{nonce}\nexit\n').encode('ascii')
    prefix = probe.UEL + b'@PJL ENTER LANGUAGE=TCLWARE\r\n' + script
    tail = b'\n' + probe.UEL + b'\r\n'
    padding = 129 - len(prefix) - len(tail)
    if padding < 1:
        raise ValueError('fixed lookup query exceeds the reviewed 129-byte profile')
    return prefix + b'#' + b' ' * (padding - 1) + tail


def parse_reply(kind, nonce, raw):
    if kind not in CASES or not re.fullmatch(r'[a-f0-9]{6}', nonce):
        raise ValueError('invalid fixed lookup case or nonce')
    argument, expected = CASES[kind]
    wanted = (f'B{nonce}\n{expected}\n\nE{nonce}\n').encode('ascii')
    if raw != wanted:
        raise ValueError('native lookup reply differs from its exact expected result')
    return {'argument': argument, 'native_result': expected,
            'pure_lookup_only': True, 'setup_emulation_applied': False}


def setup_gate_model(head_masks):
    """Offline model of the bit test at A04 0xa00f1796, not a device action.

    fb4a0(0,0) returns the AND aggregate of PH masks. The surrounding worker
    also invokes mechanical message 0x54 and accounting; those are excluded.
    """
    if (not isinstance(head_masks, (list, tuple)) or len(head_masks) != 4
            or any(type(x) is not int or not 0 <= x <= 0xffffffff for x in head_masks)):
        raise ValueError('require four uint32 masks in native B,C,M,Y order')
    intersection = 0xffffffff
    for mask in head_masks:
        intersection &= mask
    return {'all_heads_missing_bit': bool(intersection & 1),
            'and_mask': intersection,
            'scope': 'offline_final_bit_test_only',
            'priming_authorized_by_model': False}


class ProbeSession(ReadSession):
    proofs_verified = False

    def command_payload(self, kind, nonce, memory=None):
        if kind not in CASES:
            return super().command_payload(kind, nonce, memory)
        if memory is not None or not self.proofs_verified:
            raise RuntimeError('fixed native calls require successful live code proofs')
        if any(q['kind'] == kind for q in self.queries):
            raise RuntimeError('one call per case; no replay')
        return payload(kind, nonce)

    def validate_reply(self, kind, nonce, raw, memory, report):
        if kind not in CASES:
            return super().validate_reply(kind, nonce, raw, memory, report)
        report['native_lookup_proof'] = parse_reply(kind, nonce, raw)


def read_plan(client, mode, include_diagnostics=False):
    client.state.update(investigation='setup_recognition',
                        setup_emulation_applied=False, pump_commands_sent=0,
                        memory_writes_sent=0, print_jobs_created=False)
    client.identify()
    for kind in ('telemetry_diag_busy', 'telemetry_diag_printing',
                 'telemetry_diag_cover_open'):
        value = client.value(kind)
        if value != '0':
            raise RuntimeError('fixed native lookup requires an idle closed printer: ' + kind)
    proofs = []
    for name, address, length, digest in PROOFS:
        data = b''.join(client.memory(address + offset, min(128, length - offset))
                        for offset in range(0, length, 128))
        actual = hashlib.sha256(data).hexdigest()
        if actual != digest:
            raise RuntimeError('live native lookup proof differs: ' + name)
        proofs.append({'name': name, 'address': hex(address),
                       'length': length, 'sha256': actual})
    client.state['native_code_proofs'] = proofs
    client.session.proofs_verified = True
    for kind in CASES:
        reply = client.query(kind)
        client.state.setdefault('native_lookups', []).append(
            reply['transport']['native_lookup_proof'])
    # Read actual statuses without invoking the servicing worker or changing
    # its state. Suffix order differs from the native order.
    masks = [int(client.value('telemetry_head_native_' + str(suffix)), 0)
             for suffix in (3, 0, 1, 2)]
    client.state['head_masks_BCMY'] = masks
    client.state['setup_gate_model'] = setup_gate_model(masks)
    client.state['ids_fsm_state_raw'] = struct.unpack('>I', client.memory(0xa039d3e4, 4))[0]
    client.identify()
    client.state['complete'] = True


def collect(cutoff):
    needed = {'command_payload', 'validate_reply', 'phase_limit',
              'drain_payload', 'reply_end_seen'}
    if not needed.issubset(ReadSession.query.__code__.co_names):
        raise RuntimeError('setup probe requires matching batch_usb.py hook interfaces')
    # These two hooks are scoped to this one-shot process; installed services
    # and module files are untouched. The standard collector retains its lock,
    # device guard, identity checks, trace, checkpoints and cleanup rules.
    original_session, original_plan = batch_read.ReadSession, batch_read.read_content
    try:
        batch_read.ReadSession, batch_read.read_content = ProbeSession, read_plan
        return batch_read.collect(cutoff, 'diagnostics', False, True, 63)
    finally:
        batch_read.ReadSession, batch_read.read_content = original_session, original_plan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--until-utc', required=True)
    args = parser.parse_args()
    client = collect(dt.datetime.fromisoformat(args.until_utc))
    import json
    print(json.dumps({'session': str(client.target), 'batch': client.state['batch_report'],
                      'complete': client.state['complete'],
                      'native_lookups': client.state.get('native_lookups'),
                      'setup_emulation_applied': False}))


if __name__ == '__main__':
    main()
