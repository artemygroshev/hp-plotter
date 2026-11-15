"""Fixed Tcl reply controls without printhead, motor or persistent writes.

The probes reproduce the S/R/E framing of a recovery reply, but catch only
an empty script or a deliberate Tcl error. They cannot establish whether a
previous servicing operation succeeded. No CLI or automatic servicing retry.
"""
import re

from quiet_end_reads import QuietEndReadSession
import probe_printer as probe


PROFILES = {
    'reply_probe_unflushed_zero': ('', False, 0),
    'reply_probe_flushed_zero': ('', True, 0),
    'reply_probe_flushed_error': ('error REPLY_PROBE', True, 1),
}


def probe_script(kind, nonce):
    if not re.fullmatch(r'[a-f0-9]{6}', nonce):
        raise ValueError('require a fresh six-hex nonce')
    if kind not in PROFILES:
        raise ValueError('only the three fixed reply controls are allowed')
    body, flush, _ = PROFILES[kind]
    return ('puts S' + nonce + '\nflush stdout\n'
            'puts R' + nonce + '_[catch {' + body + '}]\n'
            + ('flush stdout\n' if flush else '')
            + 'puts E' + nonce + '\n'
            + ('flush stdout\n' if flush else '')
            + 'exit\n').encode('ascii')


def probe_payload(kind, nonce):
    prefix = probe.UEL + b'@PJL ENTER LANGUAGE=TCLWARE\r\n' + probe_script(kind, nonce)
    tail = b'\n' + probe.UEL + b'\r\n'
    padding = 257 - len(prefix) - len(tail)
    if padding < 1:
        raise ValueError('reply probe exceeds reviewed frame size')
    return prefix + b'#' + b' ' * (padding - 1) + tail


def parse_probe_reply(kind, nonce, raw):
    # Validate both selectors even when this function is called independently.
    probe_script(kind, nonce)
    code = PROFILES[kind][2]
    expected = ('S' + nonce + '\nR' + nonce + '_' + str(code)
                + '\nE' + nonce + '\n').encode('ascii')
    if raw != expected:
        raise ValueError('reply probe requires exact fresh S/result/E, with no lost line')
    return {'profile': kind, 'expected_catch_code': code,
            'complete_reply_verified': True, 'mechanical_calls': 0,
            'previous_recovery_success_proven': False}


class ReplyProbeSession(QuietEndReadSession):
    def command_payload(self, kind, nonce, memory=None):
        if kind not in PROFILES:
            return super().command_payload(kind, nonce, memory)
        if memory is not None:
            raise ValueError('reply controls have no memory arguments')
        return probe_payload(kind, nonce)

    def validate_reply(self, kind, nonce, raw, memory, report):
        if kind not in PROFILES:
            return super().validate_reply(kind, nonce, raw, memory, report)
        report['reply_probe_proof'] = parse_probe_reply(kind, nonce, raw)
