"""Reproduce the A.04.02 read-only PML table offline; never opens a network/device."""
from pathlib import Path
import hashlib
import json
import struct

ROOT = Path(__file__).resolve().parents[1]
BASE = 0xa0001000
SHA256 = 'c882e68d2eb2462745f1ec984ce8f5ed745d2900587dce6b36acee5b89a1f4eb'
TABLE = 0xa0389c74
COUNT = 74
STRIDE = 44
SNMP_PREFIX = '1.3.6.1.4.1.11.2.3.9.4.2.'


def extract(data):
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('require the independently verified A.04.02 main image')

    def read(address, size):
        offset = address-BASE
        if not 0 <= offset <= len(data)-size:
            raise ValueError('pointer outside the pinned image')
        return data[offset:offset+size]

    def text(address):
        if not address:
            return None
        raw = read(address, 96)
        end = raw.find(b'\0')
        if end < 1:
            raise ValueError('native ODB name missing/beyond bound')
        return raw[:end].decode('ascii')

    objects = []
    for index in range(COUNT):
        address = TABLE+index*STRIDE
        words = struct.unpack('>11I', read(address, STRIDE))
        if words[1] != index or words[6] != 0:
            raise ValueError('unexpected table index or non-null set handler')
        count = int.from_bytes(read(words[0], 2), 'big')
        if not 1 <= count <= 16:
            raise ValueError('unexpected OID length')
        relative = '.'.join(str(x) for x in read(words[0]+2, count))
        if read(words[5], 2) != b'\x4e\x56':
            raise ValueError('get handler does not start with expected LINK')
        objects.append({'index': index, 'descriptor_address': hex(address),
            'relative_pml_oid': relative,
            'candidate_snmp_oid': SNMP_PREFIX+relative+'.0',
            'descriptor_raw_words': [hex(x) for x in words],
            'get_handler': hex(words[5]), 'set_handler': None,
            'odb_name': text(words[8]),
            'callback': hex(words[10]) if words[10] else None})
    if read(TABLE+COUNT*STRIDE, 4) != bytes(4):
        raise ValueError('table terminator differs')
    if len({o['relative_pml_oid'] for o in objects}) != COUNT:
        raise ValueError('duplicate OID')
    return objects


def main():
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_image',type=Path)
    args=parser.parse_args()
    objects=extract(args.main_image.read_bytes())
    print(json.dumps({'source_sha256':SHA256,'objects':objects,
      'live_values_read':False,'snmp_mapping_hardware_validated':False},indent=2))


if __name__ == '__main__':
    main()
