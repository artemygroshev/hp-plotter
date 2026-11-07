"""Decode an already captured panel image; no printer or network operations."""
import argparse
from io import BytesIO
from pathlib import Path
import re
from PIL import Image


def decode(data, allow_hp_a04=False):
    if len(data) > 65536:
        raise ValueError('capture exceeds one-frame inspection limit')
    candidates = []
    hp_quirk_starts = set()
    if allow_hp_a04:
        # Exact A.04.02 fpDumpDisplay header, independently observed and
        # explained by its word/byte size calculation. Never pad missing data.
        known_header = bytes.fromhex(
            '424d3e010000000000003e00000028000000800000004000000001000100'
            '0000000000010000d8090000d80900000000000000000000ffffff0000000000')
        for marker in re.finditer(re.escape(b'1086\n' + known_header), data):
            start = marker.start() + 5
            hp_quirk_starts.add(start)
            if len(data) - start < 1086:
                continue
            # This bridge has inserted/repeated 64-byte blocks. A valid BMP
            # prefix does not justify silently ignoring unexplained tail data.
            if data[:marker.start()] not in (b'', b'\n', b'\r\n'):
                continue
            if data[start+1086:] not in (b'', b'\n', b'\r\n', b'1086\n', b'\n1086\n', b'\r\n1086\r\n'):
                continue
            frame = bytearray(data[start:start+1086])
            frame[2:6] = (1086).to_bytes(4, 'little')
            frame[34:38] = (1024).to_bytes(4, 'little')
            candidates.append(bytes(frame))
    for xbm in re.finditer(rb'#define\s+\w+_width\s+128\b', data):
        end = data.find(b'}', xbm.start())
        if end >= 0:
            candidates.append(data[xbm.start():end+1] + b';\n')
    for bmp in re.finditer(b'BM', data):
        start = bmp.start()
        if start in hp_quirk_starts: continue
        if len(data)-start < 14: continue
        size = int.from_bytes(data[start+2:start+6], 'little')
        if 14 <= size <= len(data)-start:
            candidates.append(data[start:start+size])
    if len(candidates) > 128:
        raise ValueError('too many candidate frames')
    decoded = []
    for frame in candidates:
        try:
            with Image.open(BytesIO(frame)) as image:
                if image.size != (128, 64): continue
                decoded.append(image.convert('RGB'))
        except (ValueError, OSError):
            continue
    if len(decoded) != 1:
        raise ValueError(('expected exactly one complete panel frame', len(decoded)))
    return decoded[0]


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('capture', type=Path)
    p.add_argument('output_png', type=Path)
    p.add_argument('--hp-a04', action='store_true', help='allow exact verified A.04.02 length-header anomaly, still require all pixels')
    args = p.parse_args()
    if args.output_png.exists():
        raise SystemExit('output already exists; choose another filename')
    decode(args.capture.read_bytes(), allow_hp_a04=args.hp_a04).save(args.output_png)
