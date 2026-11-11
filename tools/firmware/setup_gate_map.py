"""Extract the A.04.02 Setup recognition state transitions, without USB access.

The HP firmware image must be supplied locally; it is not redistributed here.
This prints a map, never a patched firmware image or a device command.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

BASE = 0xa0001000
IMAGE_SHA256 = 'c882e68d2eb2462745f1ec984ce8f5ed745d2900587dce6b36acee5b89a1f4eb'


def extract(data):
    if hashlib.sha256(data).hexdigest() != IMAGE_SHA256:
        raise ValueError('require the pinned official A.04.02 engine image')

    def label(table, number):
        target, = struct.unpack_from('>I', data, table - BASE + number * 4)
        if data[target - BASE:target - BASE + 2] != b'\x20\x3c':
            raise ValueError('state-name renderer has a different instruction')
        pointer, = struct.unpack_from('>I', data, target - BASE + 2)
        offset = pointer - BASE
        end = data.index(b'\0', offset, offset + 100)
        return data[offset:end].decode('ascii')

    transitions = []
    for index in range(348):
        address = 0xa039d3fc + 28 * index
        state, event_type, event, timeout, guard, following, action = struct.unpack_from(
            '>7I', data, address - BASE)
        if state in (26, 35, 37) and (event in (17, 18, 22) or event_type == 1):
            transitions.append({'address': hex(address), 'state': state,
                'state_name': label(0xa00f1adc, state), 'event_type': event_type,
                'event': event, 'event_name': 'timeout' if event_type == 1 else label(0xa00f194c, event),
                'timeout_raw': timeout, 'guard': hex(guard), 'following': following,
                'following_name': label(0xa00f1adc, following), 'action': hex(action)})
    if label(0xa00f1adc, 35) != 'PG_WAIT_INST_SETUP_CHECK':
        raise ValueError('Setup state identity differs')
    # This is the final bit test, not the complete servicing worker.
    if data[0xa00f1796 - BASE:0xa00f17a0 - BASE] != bytes.fromhex('08000000670470016008'):
        raise ValueError('Setup recognition final bit test differs')
    return {'scope': 'offline_reverse_engineering_only', 'image_sha256': IMAGE_SHA256,
            'table_address': '0xa039d3fc', 'table_entries': 348, 'entry_bytes': 28,
            'final_gate': {'worker': '0xa00f1710', 'test': '0xa00f1796',
                'source': 'fb4a0(0,0): AND of four PH-STATUS masks',
                'acceptance_condition': '(and_mask & 1) != 0',
                'hardware_message_before_test': '0x54',
                'worker_is_safe_pure_getter': False,
                'offline_candidate': {'address': '0xa00f179a',
                    'original_word': '6704', 'candidate_word': '4e71',
                    'effect': 'fall through to return 1 regardless of the final missing-head bit',
                    'scope': 'shared missing-head check, including removal and Setup phases',
                    'rollback_word': '6704', 'applied_to_device': False,
                    'live_write_and_cache_rollback_verified': False}},
            'transitions': transitions, 'override_implemented': False,
            'device_commands_sent_by_this_tool': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('engine_image', type=Path)
    args = parser.parse_args()
    print(json.dumps(extract(args.engine_image.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
