"""Offline A.04.02 capability evidence. Never opens USB or executes printer code.

The catalogue covers one recognized Tcl registration pattern, not every firmware
function. A registration is not a permission, a safety assessment or live proof.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from readback_map import BASE, EXPECTED, registrations

REGISTER = '0xa0320330'
FUNCTIONS = {
    'head_subcode': (0xa00ef4ac, 0xd6,
        '8c4b06fd8766d39336a5c4aa489f3cd306a58178281d7b89eb67d38f491b718b'),
    'head_full_code': (0xa00ef628, 0xbe,
        '3d82b60e487932ec7988ed10e062df37d2eab012c4fa65b7ffb8766890bc6565'),
    'error_record_reader': (0xa0295818, 0xc2,
        '673fd161b07278c75a7ea009384f39713384b0686a70a0e3d4ed6599f7ae0d42'),
    'panel_status': (0xa027c068, 0x1c,
        '0a5020f3710cd9845856fd225628c3528e1983a3117d08a19488833ab0232bfc'),
}
REVIEW = {
    'sysGetFwRevision': 'live_fixed_arguments',
    'sysODBGet': 'live_30_fixed_objects_only',
    'osMemDump': 'live_bounded_addressed_RAM_only',
    'osFuncCall': 'live_one_verified_LCD_getter_only',
    'fpDumpDisplay': 'native_BMP_transport_rejected',
    'fpGetStatus': 'static_two_result_status_not_error_text',
    'fpGetPressedKey': 'unverified_can_wait_or_consume_key',
    'fpSimulateKey': 'static_event_injection_not_enabled',
    'fpMenuFocus': 'changes_menu_not_enabled',
    'fpGetFrontPanel': 'claims_panel_not_enabled',
    'fpReleaseFrontPanel': 'changes_panel_ownership_not_enabled',
    'sysODBSet': 'writes_device_state_not_enabled',
    'eeReadEeromMem': 'static_candidate_arguments_and_output_unverified',
    'eeReadEeromByteArray': 'static_candidate_arguments_and_output_unverified',
    'eeResetEeromMem': 'changes_persistent_state_not_enabled',
    'sysLogClear': 'changes_logging_configuration_not_error_history_reader',
    'sysCleanResetInfo': 'clears_diagnostic_information_not_enabled',
    'sysShowResetInfo': 'candidate_reset_information_not_system_error_history',
}


def extract(data):
    if hashlib.sha256(data).hexdigest() != EXPECTED:
        raise ValueError('require the pinned official A.04.02 main image')

    def read(address, length):
        offset = address - BASE
        if not 0 <= offset <= len(data)-length:
            raise ValueError('pointer outside pinned image')
        return data[offset:offset+length]

    def cstring(address):
        raw = read(address, 96)
        end = raw.find(b'\0')
        if end <= 0:
            raise ValueError('missing bounded object name')
        return raw[:end].decode('ascii')

    matched = {name: row for name, row in registrations(data).items()
               if row['registration_call_target'] == REGISTER}
    if len(matched) != 403 or not all(row['handler_link_prologue'] for row in matched.values()):
        raise ValueError('registration evidence differs')
    commands = [dict(name=name, **matched[name],
                     review=REVIEW.get(name, 'not_assessed_not_enabled'))
                for name in sorted(matched)]
    proofs = {}
    for name, (address, length, expected) in FUNCTIONS.items():
        digest = hashlib.sha256(read(address, length)).hexdigest()
        if digest != expected:
            raise ValueError('function evidence differs: '+name)
        proofs[name] = dict(address=hex(address), bytes=length, sha256=digest)

    # Native device index, ODB suffix and LCD position are different namespaces.
    descriptors = []
    for slot in range(4):
        address = 0xa039d324 + 22*slot
        raw = read(address, 22)
        descriptors.append(dict(address=hex(address),
            odb_name=cstring(struct.unpack_from('>I', raw)[0]),
            native_device_index=struct.unpack_from('>I', raw, 8)[0],
            error_color_prefix=raw[16]))
    if [(x['odb_name'], x['native_device_index'], x['error_color_prefix'])
        for x in descriptors] != [('PH-STATUS-3', 0, 0), ('PH-STATUS-0', 1, 2),
                                  ('PH-STATUS-1', 2, 1), ('PH-STATUS-2', 3, 3)]:
        raise ValueError('native head mapping differs')

    # Reviewed path only for this exact mask. No generic decoder is claimed.
    if read(0xa00ef568, 10) != bytes.fromhex('0801001367047021600c'):
        raise ValueError('bit-19 to decimal-33 path differs')
    mask = 0x80000
    black = next(row for row in descriptors if row['odb_name'] == 'PH-STATUS-3')
    prefix = black['error_color_prefix'] + (10 if mask & 8 else 0)
    known_case = dict(odb_name='PH-STATUS-3', raw_mask=mask,
        native_device_index=black['native_device_index'],
        subcode=33, derived_code=f'{prefix*100+33:04d}',
        provenance='offline_derived_from_exact_mask_not_read_from_error_log',
        physical_cause_proven=False)

    tags = list(struct.unpack('>10I', read(0xa0296448, 40)))
    if tags != list(range(811, 821)):
        raise ValueError('ten error-record tags differ')
    return dict(schema=1, firmware='A.04.02', image_sha256=EXPECTED,
        evidence_kind='offline_static_analysis',
        catalogue_is_complete_firmware_API=False,
        live_queries_performed_by_this_tool=0,
        commands_matching_this_registration_pattern=commands,
        command_count=len(commands), function_proofs=proofs,
        head_index_mapping=descriptors, known_head_case=known_case,
        system_error_log_candidate=dict(group=8, record_tags=tags,
            record_bytes=20, ring_index_tag=810,
            read_function='0xa0295818',
            live_read_implemented=False, layout_fully_validated=False),
        limits=['No arbitrary command runner is generated.',
                'Static presence does not establish output route or safe arguments.',
                'The exact-mask head code is derived, not a retrieved history entry.',
                'A diagnostic code does not identify a uniquely faulty physical part.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_image', type=Path)
    args = parser.parse_args()
    print(json.dumps(extract(args.main_image.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
