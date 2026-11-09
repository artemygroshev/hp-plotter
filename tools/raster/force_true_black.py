"""Select the reviewed DesignJet 500 True black mode in one cdnj500 job.

Only a recognized COLOR line before the single PCL3GUI entry is replaced.
The raster, job end and all other bytes are preserved. No printer is opened.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

UEL = b'\x1b%-12345X'
COLOR = b'@PJL SET RENDERMODE = COLOR \n'
TRUE_BLACK = b'@PJL SET RENDERMODE = TRUEBLACK \n'
ENTER = b'@PJL ENTER LANGUAGE=PCL3GUI \n'


def force_true_black(data):
    if not isinstance(data, bytes) or not data.startswith(UEL):
        raise ValueError('expected a UEL-framed cdnj500 byte stream')
    if data.count(ENTER) != 1:
        raise ValueError('expected exactly one PCL3GUI job')
    split = data.index(ENTER)
    if split > 4096:
        raise ValueError('unrecognized oversized PJL header')
    header, raster = data[:split], data[split:]
    modes = re.findall(rb'(?m)^@PJL\s+SET\s+RENDERMODE\s*=[^\r\n]*', header)
    if header.count(COLOR) != 1 or len(modes) != 1:
        raise ValueError('expected exactly the reviewed COLOR setting')
    if b'@PJL JOB NAME=' not in header or b'@PJL EOJ' not in raster:
        raise ValueError('job scope and end must be present')
    if COLOR in raster or b'@PJL DEFAULT' in data or b'@PJL INITIALIZE' in data:
        raise ValueError('unexpected render/default command outside the reviewed header')
    return header.replace(COLOR, TRUE_BLACK, 1) + raster


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    source = args.input.read_bytes()
    result = force_true_black(source)
    with args.output.open('xb') as stream:
        stream.write(result)
    print(json.dumps({'input_bytes': len(source), 'output_bytes': len(result),
        'input_sha256': hashlib.sha256(source).hexdigest(),
        'output_sha256': hashlib.sha256(result).hexdigest(),
        'selected_mode': 'TRUEBLACK', 'scope': 'one PJL job',
        'raster_bytes_unchanged': True}))


if __name__ == '__main__':
    main()
