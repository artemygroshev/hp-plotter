"""Frame already validated native commands with an HP tick continuity check.

This is not command authorization. The caller must validate fixed native
addresses, arguments, ownership, live code and a current positive tick floor.
The guard detects a lower tick count; it is not a unique firmware boot ID.
There is no USB access, retry or recovery in this module.
"""
import re

import probe_printer as probe

SUPPRESSED = -2147483648


def frame(commands, nonce, minimum_ticks):
    if (not re.fullmatch(r'[a-f0-9]{6}', nonce)
            or type(minimum_ticks) is not int or not 0 < minimum_ticks < 0x7fffffff
            or not isinstance(commands, (list, tuple)) or not 1 <= len(commands) <= 4
            or any(not isinstance(command, str) or not re.fullmatch(
                r'(?:osMemAlloc 1024|osMemFree 0x[a-f0-9]+|osFuncCall 0x[a-f0-9]+ [0-3](?: (?:0x[a-f0-9]+|[0-9]+))*)', command)
                   for command in commands)):
        raise ValueError('require a fresh nonce, positive tick floor and validated native commands')
    success = '\n'.join('puts [' + command + ']' for command in commands)
    refused = '\n'.join('puts ' + str(SUPPRESSED) for _ in commands)
    script = (f'puts B{nonce}\nif {{[sysTickGet] >= {minimum_ticks}}} {{\n'
              + success + '\n} else {\n' + refused + f'\n}}\nputs E{nonce}\nexit\n').encode('ascii')
    prefix = probe.UEL + b'@PJL ENTER LANGUAGE=TCLWARE\r\n' + script
    tail = b'\n' + probe.UEL + b'\r\n'
    length = 513 if len(commands) > 1 else 257
    padding = length - len(prefix) - len(tail)
    if padding < 1:
        raise ValueError('guarded script exceeds its fixed frame size')
    return prefix + b'#' + b' ' * (padding - 1) + tail
