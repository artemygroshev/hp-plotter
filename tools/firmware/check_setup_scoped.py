"""Compare every scoped-experiment instruction with GNU ColdFire assembly.

Offline only. The assembler must accept each instruction's operands for each
CPU, and its complete bytes must match the generator, including relocations.
This does not validate a printer's cache, scheduler or physical ink system.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from check_ram_coldfire import source_for
from setup_scoped_roundtrip import build


def check(assembler, objcopy, workspace):
    p = build(workspace)
    parts = (('transaction', p['code'], workspace),
             ('wrapper', p['wrapper_code'], p['wrapper']),
             ('scoped_hook', p['hook_code'], p['hook']))
    checks = []
    environment = dict(os.environ, LC_ALL='C')
    with tempfile.TemporaryDirectory(prefix='hp-scoped-coldfire-') as temporary:
        root = Path(temporary)
        for name, code, address in parts:
            source = source_for(code, address)
            for cpu in ('5206', '5307', '5475'):
                obj, binary = root / (name + cpu + '.o'), root / (name + cpu + '.bin')
                result = subprocess.run([assembler, '--register-prefix-optional', '-mcpu=' + cpu,
                                         '-o', str(obj), '-'], input=source, text=True,
                                        capture_output=True, timeout=20, env=environment)
                if result.returncode:
                    raise RuntimeError('GNU rejected %s for %s: %s' % (name, cpu, result.stderr))
                subprocess.run([objcopy, '-O', 'binary', '-j', '.text', str(obj), str(binary)],
                               capture_output=True, check=True, timeout=20, env=environment)
                if binary.read_bytes() != code:
                    raise RuntimeError('GNU bytes differ for %s/%s' % (name, cpu))
                checks.append({'part': name, 'address': hex(address), 'cpu': cpu,
                               'bytes': len(code), 'sha256': hashlib.sha256(code).hexdigest(),
                               'exact_bytes_match': True})
    return {'scope': 'offline_instruction_encoding_only', 'workspace': hex(workspace),
            'device_access': False, 'checks': checks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assembler', default='m68k-linux-gnu-as')
    parser.add_argument('--objcopy', default='m68k-linux-gnu-objcopy')
    parser.add_argument('--workspace', type=lambda s: int(s, 0), default=0xa0800000)
    args = parser.parse_args()
    print(json.dumps(check(args.assembler, args.objcopy, args.workspace), indent=2))


if __name__ == '__main__':
    main()
