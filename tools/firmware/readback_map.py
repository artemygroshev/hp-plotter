"""Offline A.04.02 evidence for readback candidates; never contacts a printer.

Names and registration links are static evidence, not a list of safe commands.
No generated Tcl or live call is made. Disassembly stops at function return.
"""
from pathlib import Path
import hashlib
import json
import re
import struct
import sys

ROOT = Path(__file__).resolve().parent
BASE = 0xA0001000
EXPECTED = 'c882e68d2eb2462745f1ec984ce8f5ed745d2900587dce6b36acee5b89a1f4eb'
SELECTED = (
    'fpDumpDisplay', 'fpGetStatus', 'sysGetFwRevision', 'sysGetBoardInfo',
    'sysODBGet', 'sysODBDump', 'gasGaugeGetUsedInk', 'gasGaugeGetNominalDropWeight',
    'penGetTemp', 'getAmbientTSensorStatus', 'osSemShow', 'osMsgQShow',
)
OBJECTS = (
    'DEV-SERIAL-NUMBER', 'DEV-MODEL-NUMBER', 'ERROR-STATE',
    'PERIPHERAL-B-ERROR', 'PERIPHERAL-NB-ERROR', 'IO-STATUS-INK-OUT',
    'IO-PERIPH-STATUS', 'MEDIA-INPUT-PRESENT', 'MEDIA-SRC', 'FP-MEDIA-NAME',
    'FP-MEDIA-VENDOR', 'PH-STATUS-0', 'PH-STATUS-1', 'PH-STATUS-2', 'PH-STATUS-3',
    'CRTGE-STATUS-0', 'CRTGE-STATUS-1', 'CRTGE-STATUS-2', 'CRTGE-STATUS-3',
    'CRTGE-CONSUM-0-INK-0', 'CRTGE-CONSUM-1-INK-0',
    'CRTGE-CONSUM-2-INK-0', 'CRTGE-CONSUM-3-INK-0',
)


def registrations(data):
    found = {}
    pattern = rb'\x48\x79(.{4})\x48\x79(.{4})\x2f\x0d\x4e\xb9(.{4})'
    for match in re.finditer(pattern, data, re.S):
        handler, name, call = (struct.unpack('>I', x)[0] for x in match.groups())
        offset = name - BASE
        if not 0 <= offset < len(data):
            continue
        end = data.find(b'\0', offset, offset + 100)
        if end < 0:
            continue
        text = data[offset:end]
        if re.fullmatch(rb'[A-Za-z][A-Za-z0-9_]*', text):
            found[text.decode()] = {
                'handler': hex(handler), 'name_address': hex(name),
                'registration_address': hex(BASE + match.start()),
                'registration_call_target': hex(call),
                'handler_link_prologue': data[handler-BASE:handler-BASE+2] == b'\x4e\x56',
            }
    return found


def references(data, address):
    return [BASE + m.start() for m in re.finditer(re.escape(struct.pack('>I', address)), data)]


def disassemble_function(data, address, decoder, limit=1400):
    start = address - BASE
    if data[start:start+2] != b'\x4e\x56':
        raise ValueError('no expected function prologue')
    lines = []
    end = min(len(data), start + limit)
    for ins in decoder.disasm(data[start:end+32], address):
        if ins.address >= BASE + end:
            break
        lines.append('%08x %-11s %s' % (ins.address, ins.mnemonic, ins.op_str))
        if ins.mnemonic == 'rts':
            return lines
    raise ValueError('function end not found inside bound: ' + hex(address))


def inspect():
    data = (ROOT / 'engine-A0402-main.bin').read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED:
        raise ValueError('A.04.02 main image SHA256 differs')
    all_commands = registrations(data)
    result = {
        'image_sha256': digest, 'candidate_load_address': hex(BASE),
        'evidence_kind': 'static_analysis_only', 'runtime_reply_received': False,
        'commands': {name: all_commands[name] for name in SELECTED},
        'object_name_candidates': {},
        'serial_restriction': {
            'message_references': [], 'restricted_implementations': ['0xa028eee8', '0xa028ef28'],
            'commands': ['osSemShow', 'osMsgQShow'],
            'lcd_restriction_not_implied': True,
        },
    }
    for name in OBJECTS:
        needle = name.encode() + b'\0'
        locations = [m.start() for m in re.finditer(re.escape(needle), data)]
        result['object_name_candidates'][name] = [
            {'name_address': hex(BASE + location),
             'references': [hex(x) for x in references(data, BASE + location)]}
            for location in locations
        ]
    message = b'Function not available through this output. Only available on serial port connection'
    offset = data.index(message)
    result['serial_restriction']['message_references'] = [hex(x) for x in references(data, BASE+offset)]
    sys.path.insert(0, str(ROOT / 'analysis-libs'))
    from capstone import Cs, CS_ARCH_M68K, CS_MODE_M68K_040
    decoder = Cs(CS_ARCH_M68K, CS_MODE_M68K_040)
    regions = {name: int(all_commands[name]['handler'], 16) for name in SELECTED}
    regions.update({'serial_guard_sem': 0xa028eee8, 'serial_guard_msgq': 0xa028ef28})
    regions.update({'pjl_info_parser': 0xa02fbd08, 'pjl_callback_install': 0xa02fadc4,
                    'pjl_callback_initializer': 0xa02880bc, 'pjl_info_callback': 0xa0287f84})
    callback_table = struct.unpack_from('>10I', data, 0xa02881ec-BASE)
    if callback_table[7] != regions['pjl_info_callback']:
        raise ValueError('PJL INFO callback table changed')
    literals = {}
    for address in (0xa02882fc, 0xa0288300, 0xa028830c, 0xa0288314):
        offset = address - BASE
        literals[hex(address)] = data[offset:data.index(b'\0', offset)].decode('ascii')
    if list(literals.values()) != ['ID', '"HYDRA"\r\n', 'MEMORY', 'TOTAL=25165824\r\n']:
        raise ValueError('PJL INFO callback literals changed')
    result['pjl_info'] = {
        'parser': hex(regions['pjl_info_parser']), 'callbacks_base': '0xa044a860',
        'info_slot_offset': '0x1c', 'initializer': '0xa02880bc',
        'copy_function': '0xa02fadc4', 'source_table': '0xa02881ec',
        'info_callback': hex(callback_table[7]), 'callback_literals': literals,
        'callback_handles': ['ID', 'MEMORY'],
        'STATUS_recognized_by_parser_but_not_handled_by_this_callback': True,
        'unknown_response_literal': '"?"\r\n',
        'runtime_callback_pointer_not_read': True,
        'hardcoded_memory_not_a_runtime_measurement': True,
    }
    text = []
    for name, address in regions.items():
        text.append('REGION ' + name)
        text.extend(disassemble_function(data, address, decoder))
        text.append('')
    result['serial_restriction']['wrapper_call_checks'] = {
        'osSemShow': bool(re.search(r'\bjsr\s+\$a028eee8\.l', '\n'.join(disassemble_function(data, regions['osSemShow'], decoder)))),
        'osMsgQShow': bool(re.search(r'\bjsr\s+\$a028ef28\.l', '\n'.join(disassemble_function(data, regions['osMsgQShow'], decoder)))),
    }
    if not all(result['serial_restriction']['wrapper_call_checks'].values()):
        raise ValueError('serial guard call chain changed')
    return result, '\n'.join(text)


if __name__ == '__main__':
    report, assembly = inspect()
    output = ROOT.parent / 'panel-live-20261107'
    for filename, content in [('readback-static-map.json', json.dumps(report, indent=2)),
                              ('readback-static-functions.txt', assembly)]:
        path = output / filename
        if path.exists():
            raise FileExistsError(path)
        path.write_text(content + '\n')
        path.chmod(0o600)
    print(json.dumps({'selected_commands': len(report['commands']),
                      'object_names_with_matches': sum(bool(v) for v in report['object_name_candidates'].values()),
                      'serial_restriction': report['serial_restriction']}, indent=2))
