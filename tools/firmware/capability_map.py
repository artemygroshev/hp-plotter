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
    'eerom_binary_as_string': (0xa02753fc, 0x110,
        '8997c22e6fabbf973ae002a4e1993b18fe9f034ca06e89f80626c392b76ff318'),
    'eerom_byte_element': (0xa027550c, 0xb0,
        '6bcb7da9e4321c7dd0c0a7d7f0f79059f6721cc3cd5062629ee8c582df9bc0af'),
    'eerom_name_to_group': (0xa0274d8c, 0x130,
        '3c782e9e67a6a915dcc1a2fec0c65cb74e23e3f6003f4513709c621a01e0f6b2'),
    'main_descriptor_lookup': (0xa01161b0, 0xa4,
        '88b831012ec4aeaad6f7c19bd5bd96fa6ddf2e374701a64b8311b7973bd09663'),
    'main_RAM_copy_reader': (0xa0113ad0, 0xcc,
        '29098132a24500b823c609b79aa82d485636dd954324469e7aceb6e4a1cedf74'),
    'head_history_reader': (0xa00f6354, 0x1a8,
        '91f30cda8cecf7a2eae23cbf47ec7a11be79a080f80197a30056b7f3ff0a3085'),
    'head_history_index_getter': (0xa00f6158, 0xfc,
        '473490f344ac5f0c23bc755395463a0d06b3d1178948015d7f5725a7488e203e'),
    'previous_reset_Tcl_wrapper': (0xa026cf5c,60,
        '08d43af2eb56ccebaf51d4136ad0af5957937b62dc3673083620dd4dce9481e1'),
    'previous_reset_native_report': (0xa010c0e8,290,
        '288145d01f4dad93bf0fd13becd554d431393931131bc30e0e8fae98e2330596'),
    'writing_system_ODB_handles': (0xa007a388,520,
        'c8b90532fd30cf638b31147305649d607e3cd4b4db3978b4bdef8bb4ee304f7e'),
    'writing_system_set_bit': (0xa007b430,212,
        '194542c7ffaa26dd30e5584cc0c6a51d9eab16462e943d4970b3f00a629e20cf'),
    'head_status_aggregate_callback': (0xa00fb3d0,208,
        'd3848bacc97407e5a9b24d142966ccc45e7eb7375e6c610d03a9b3067ef17b94'),
    'head_status_aggregate_initialization': (0xa00fb4f4,770,
        '4f8f4253e04a8afbf2c8f3e7f6b49ebaac1082264923eb2bf595a3e92bc212e0'),
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
    'eeReadEeromByteArray': 'static_binary_as_string_can_truncate_not_enabled',
    'eeReadEeromByteArrayElement': 'static_zero_ambiguous_with_read_failure_not_enabled',
    'eeResetEeromMem': 'changes_persistent_state_not_enabled',
    'sysLogClear': 'changes_logging_configuration_not_error_history_reader',
    'sysCleanResetInfo': 'clears_diagnostic_information_not_enabled',
    'sysShowResetInfo': 'prepared_fixed_previous_reset_report_live_not_yet_verified',
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
    names = {cstring(0xa0276454): 8, cstring(0xa027645c): 9}
    if names != {'MAIN': 8, 'BACKUP': 9} or cstring(0xa02765f4) != '%s':
        raise ValueError('EEROM name/output evidence differs')
    return dict(schema=1, firmware='A.04.02', image_sha256=EXPECTED,
        evidence_kind='offline_static_analysis',
        catalogue_is_complete_firmware_API=False,
        live_queries_performed_by_this_tool=0,
        commands_matching_this_registration_pattern=commands,
        command_count=len(commands), function_proofs=proofs,
        head_index_mapping=descriptors, known_head_case=known_case,
        writing_system_head_error_bit=dict(ODB_name='WS-B-ERROR',bit=4,value=16,
            head_error_mask=0x04feffe1,head_ODB_suffixes=[0,1,2,3],
            provenance='offline_head_status_OR_and_bit_set_paths',
            physical_cause_proven=False),
        previous_reset_report=dict(command='sysShowResetInfo',arguments=[],
            implementation='tools/service/reset_info.py',live_verified=False,
            system_error_ring=False,calling_code_meaning_confirmed=False,
            reset_or_clear_enabled=False),
        system_error_log_candidate=dict(group=8, record_tags=tags,
            record_bytes=20, ring_index_tag=810,
            read_function='0xa0295818',
            native_record_function_invocation_implemented=False,
            ram_reader='tools/service/error_journal.py',layout_fully_validated=False,
            ram_mirror_group_header='0xa03a0f10',ram_mirror_config='0xa03a0fa8',
            reviewed_table_version=6,ring_offset_bytes=1426,ring_bytes=201,
            date_units_confirmed=False,
            memory_name_to_group=names,
            binary_array_string_output_is_lossless=False,
            byte_element_exposes_separate_read_status=False,
            current_design='bounded_RAM_copy_twice_without_EEPROM_function_calls'),
        head_history_ram_reader=dict(implementation='tools/service/head_journal.py',
            reviewed_table_version=6,offset_bytes=1627,bytes=302,
            record_bytes=15,records_per_color=5,native_color_order=['Black','Cyan','Magenta','Yellow'],
            native_index_getter='0xa00f6158',native_index_getter_may_write_on_invalid_index=True,
            native_functions_called_by_reader=False,
            code_is_derived_from_stored_mask_not_a_stored_four_digit_string=True),
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
