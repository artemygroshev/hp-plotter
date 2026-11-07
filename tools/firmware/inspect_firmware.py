"""Offline, reproducible inspection of a candidate HP update; never flashes it.

ZIP CRC and zlib checks establish internal integrity, not publisher authenticity.
Candidate addresses are derived separately for each image, not reused across releases.
"""
from pathlib import Path
import hashlib
import json
import re
import struct
import zipfile
import zlib

ROOT = Path(__file__).resolve().parent


def checksum(data):
    even = len(data)//2*2
    total = sum(struct.unpack('>'+str(even//2)+'H', data[:even]))
    if len(data) & 1: total += data[-1] << 8
    while total >> 16: total = (total & 65535) + (total >> 16)
    return total


def inspect(firmware_path=None):
    archive = ROOT / 'HP_DesignJet_500_800_FU_3.8-official.zip'
    if firmware_path is not None:
        firmware = Path(firmware_path).read_bytes()
        return analyze(firmware)
    with zipfile.ZipFile(archive) as z:
        if sum(i.file_size for i in z.infolist()) > 128 * 1024 * 1024:
            raise ValueError('unexpected archive expansion')
        bad = z.testzip()
        if bad: raise ValueError(('ZIP CRC mismatch', bad))
        names = [n for n in z.namelist() if Path(n).name == 'DJ500_A.05.01.fmw']
        if len(names) != 1: raise ValueError('engine image not unique')
        firmware = z.read(names[0])
    return analyze(firmware)


def analyze(firmware):
    expected = hashlib.sha256(firmware).hexdigest()
    official = json.loads((ROOT/'official-engine-images.json').read_text())
    matches = [x for x in official if x['sha256'] == expected]
    if len(matches) != 1:
        raise ValueError('image not in recorded official extraction chain')
    match = re.search(rb'DOWNLOAD HYDRA 2\n([^\n]+)\n([^\n]+)\n(\d+) (\d+)\n0\n', firmware)
    if not match: raise ValueError('unexpected container header')
    start, size = match.end(), int(match[3])
    if len(firmware[start:start+size]) != size:
        raise ValueError('truncated payload')
    computed = checksum(firmware[start:start+size])
    if computed != int(match[4]):
        raise ValueError('engine container checksum mismatch')
    zoffset = 0x400bd
    decoder = zlib.decompressobj()
    main = decoder.decompress(firmware[zoffset:], 16 * 1024 * 1024)
    if not decoder.eof or len(main) != matches[0]['main_bytes']:
        raise ValueError('unexpected main image')
    commands = {}
    base = struct.unpack_from('>I', firmware, start+0x40000+4)[0]
    for command in ['fpDumpDisplay', 'fpSimulateKey', 'fpGetStatus',
                    'fpGetFrontPanel', 'fpReleaseFrontPanel',
                    'sysGetFwRevision', 'sysGetBoardInfo', 'sysODBGet']:
        offsets = [m.start() for m in re.finditer(re.escape(command.encode()+b'\0'), main)]
        entries = []
        for offset in offsets:
            needle = struct.pack('>I', base+offset)
            for ref in [m.start() for m in re.finditer(re.escape(needle), main)]:
                row = {'string_offset': offset, 'reference_offset': ref}
                # PEA handler; PEA command name; MOVE.L A5,-(SP); JSR registration.
                if (ref >= 8 and main[ref-8:ref-6] == b'\x48\x79'
                        and main[ref-2:ref] == b'\x48\x79'
                        and main[ref+4:ref+8] == b'\x2f\x0d\x4e\xb9'):
                    handler = struct.unpack_from('>I', main, ref-6)[0]
                    row['handler_address'] = hex(handler)
                    row['registration_call_target'] = hex(struct.unpack_from('>I', main, ref+8)[0])
                    row['handler_has_link_prologue'] = (base <= handler < base+len(main)
                                                        and main[handler-base:handler-base+2] == b'\x4e\x56')
                    row['registration_pattern'] = row['handler_has_link_prologue']
                entries.append(row)
        commands[command] = entries
    return {
        'firmware_sha256': expected,
        'container_revision': match[1].decode(),
        'container_flags_text': match[2].decode(),
        'declared_payload_bytes': size,
        'declared_checksum': int(match[4]),
        'computed_checksum': computed,
        'container_checksum_valid': True,
        'payload_offset': start,
        'payload_bounds_valid': start+size <= len(firmware),
        'main_zlib_offset': zoffset,
        'main_bytes': len(main),
        'main_sha256': hashlib.sha256(main).hexdigest(),
        'candidate_load_address': hex(base),
        'commands': commands,
        'runtime_validation_performed_by_this_offline_tool': False,
        'publisher_authenticity': 'matches_recorded_official_HP_HTTPS_download',
        'firmware_modified': False,
    }


if __name__ == '__main__':
    result = inspect()
    (ROOT/'native-access-evidence.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
