"""Independently assemble every new IDS-control instruction offline.

Requires the external official A04 image, Capstone and GNU m68k binutils.
There is no USB access. This validates instruction legality, exact encoding,
layout and the two stock waiting-state names; not hardware execution or cache.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

from check_ram_coldfire import source_for
from setup_gate_map import BASE, IMAGE_SHA256
from setup_ids_control import build, WAIT_STATES, CONTROL_OFFSET, CONTROL_RECEIPT_OFFSET
from setup_worker_clone import WORKER_ADDRESS, WORKER_BYTES


def check(image, assembler, objcopy, workspace):
    if hashlib.sha256(image).hexdigest() != IMAGE_SHA256:
        raise ValueError('require the pinned official A04 image')
    stock = image[WORKER_ADDRESS - BASE:WORKER_ADDRESS - BASE + WORKER_BYTES]
    program = build(workspace, stock)
    state_names = []
    for state in WAIT_STATES:
        getter, = struct.unpack_from('>I', image, 0xa00f1adc - BASE + state * 4)
        if image[getter - BASE:getter - BASE + 2] != bytes.fromhex('203c'):
            raise ValueError('state renderer differs')
        pointer, = struct.unpack_from('>I', image, getter - BASE + 2)
        state_names.append(image[pointer - BASE:image.index(b'\0', pointer - BASE)].decode('ascii'))
    if state_names != ['PG_WAIT_WIN_OPEN_INST_SETUP', 'PG_WAIT_WIN_CLOSED_INST_SETUP']:
        raise ValueError('real Setup wait-state identities differ')
    parts = [('worker_redirect', program['worker_code'][132:140], workspace + 132),
             ('worker_hook', program['hook_code'], program['hook']),
             ('route', program['route_code'], program['route']),
             ('control', program['control_code'], program['control'])]
    checks = []
    with tempfile.TemporaryDirectory(prefix='hp-ids-control-') as temporary:
        root = Path(temporary)
        for name, code, address in parts:
            source = source_for(code, address)
            for cpu in ('5206', '5307', '5475'):
                obj, binary = root / (name + cpu + '.o'), root / (name + cpu + '.bin')
                subprocess.run([assembler, '--register-prefix-optional', '-mcpu=' + cpu,
                    '-o', str(obj), '-'], input=source, text=True, capture_output=True,
                    check=True, timeout=20, env=dict(os.environ, LC_ALL='C'))
                subprocess.run([objcopy, '-O', 'binary', '-j', '.text', str(obj), str(binary)],
                               capture_output=True, check=True, timeout=20)
                if binary.read_bytes() != code:
                    raise ValueError('instruction bytes differ: ' + name + '/' + cpu)
                checks.append({'part': name, 'address': hex(address), 'cpu': cpu,
                    'bytes': len(code), 'sha256': hashlib.sha256(code).hexdigest(), 'exact': True})
    if (len(program['blob']) != 1024 or
            program['worker_code'][:132] != stock[:132] or program['worker_code'][140:] != stock[140:] or
            program['blob'][CONTROL_RECEIPT_OFFSET:CONTROL_RECEIPT_OFFSET + 36] != bytes(36) or
            program['blob'][CONTROL_OFFSET + len(program['control_code']):] !=
            bytes(1024 - CONTROL_OFFSET - len(program['control_code']))):
        raise ValueError('owned layout, initial receipt or stock bytes differ')
    return {'scope': 'offline_GNU_instruction_and_layout_check', 'workspace': hex(workspace),
            'image_sha256': IMAGE_SHA256, 'allocation_bytes': 1024,
            'control_bytes': len(program['control_code']), 'arm_state_names': state_names,
            'checks': checks, 'device_commands': 0, 'uploaded_to_HP': False,
            'live_coordinator_available': False, 'real_Setup_test_verified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('engine_image', type=Path)
    parser.add_argument('--assembler', default='m68k-linux-gnu-as')
    parser.add_argument('--objcopy', default='m68k-linux-gnu-objcopy')
    parser.add_argument('--workspace', type=lambda value: int(value, 0), default=0xa0800000)
    args = parser.parse_args()
    print(json.dumps(check(args.engine_image.read_bytes(), args.assembler, args.objcopy,
                           args.workspace), indent=2))


if __name__ == '__main__': main()
