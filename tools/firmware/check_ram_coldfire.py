"""Independently assemble the fixed RAM program for ColdFire, entirely offline.

Requires Capstone 5 and GNU m68k binutils. Never contacts a printer. This checks
instruction encodings; it does not prove hardware cache/rollback behavior.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from ram_rollback_program import build


def source_for(code, base):
    from capstone import Cs, CS_ARCH_M68K, CS_MODE_BIG_ENDIAN, CS_MODE_M68K_040
    decoder = Cs(CS_ARCH_M68K, CS_MODE_BIG_ENDIAN | CS_MODE_M68K_040)
    instructions = list(decoder.disasm(code, base))
    if sum(item.size for item in instructions) != len(code):
        raise ValueError('decoder did not account for every program byte')
    boundaries = {item.address for item in instructions}
    lines = ['.text', '.globl _start', '_start:']
    for item in instructions:
        operands = item.op_str.replace('$', '0x')
        if item.mnemonic in ('bne.w', 'beq.w', 'bhi.w'):
            target = int(operands, 16)
            if target not in boundaries:
                raise ValueError('branch target is outside instruction boundaries')
            operands = '.L' + str(target - base)
        lines += ['.L%d:' % (item.address - base), '    ' + item.mnemonic + ' ' + operands]
    return '\n'.join(lines) + '\n'


def check(assembler, objcopy, workspace=0xa0800000):
    code = build(workspace)['code']
    source = source_for(code, workspace)
    report = {'scope': 'offline_encoding_only', 'device_access': False,
              'workspace': hex(workspace), 'bytes': len(code),
              'program_sha256': hashlib.sha256(code).hexdigest(), 'cpus': []}
    environment = os.environ.copy()
    environment['LC_ALL'] = 'C'  # Pin the negative-control diagnostic language.
    with tempfile.TemporaryDirectory(prefix='hp-coldfire-') as temporary:
        root = Path(temporary)
        for cpu in ('5206', '5307', '5475'):
            obj, binary = root / (cpu + '.o'), root / (cpu + '.bin')
            result = subprocess.run([assembler, '--register-prefix-optional', '-mcpu=' + cpu,
                                     '-o', str(obj), '-'], input=source, text=True,
                                    capture_output=True, timeout=20, env=environment)
            if result.returncode:
                raise RuntimeError('ColdFire %s assembly rejected: %s' % (cpu, result.stderr))
            subprocess.run([objcopy, '-O', 'binary', '-j', '.text', str(obj), str(binary)],
                           capture_output=True, check=True, timeout=20, env=environment)
            if binary.read_bytes() != code:
                raise RuntimeError('ColdFire %s output differs from exact builder bytes' % cpu)
            # This negative control must fail for operand legality, not a
            # missing executable/library or malformed assembler invocation.
            bad = subprocess.run([assembler, '-mcpu=' + cpu, '-o', str(root / 'bad.o'), '-'],
                                 input='.text\nmove.l #0x48505242,0xa1ffe1a8\n', text=True,
                                 capture_output=True, timeout=20, env=environment)
            if bad.returncode == 0 or 'operands mismatch' not in bad.stderr:
                raise RuntimeError('known invalid immediate-to-absolute MOVE was not rejected')
            report['cpus'].append({'cpu': cpu, 'exact_bytes_match': True,
                                   'old_encoding_rejected': True})
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assembler', default='m68k-linux-gnu-as')
    parser.add_argument('--objcopy', default='m68k-linux-gnu-objcopy')
    parser.add_argument('--workspace', type=lambda value: int(value, 0), default=0xa0800000)
    args = parser.parse_args()
    print(json.dumps(check(args.assembler, args.objcopy, args.workspace), indent=2))


if __name__ == '__main__':
    main()
