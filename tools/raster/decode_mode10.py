"""Offline inspection of cdnj500 PCL3GUI output; does not access a printer.

Decoder follows the wire format emitted by Artifex gdevcd8.c Mode10.
Validate against the upstream encoder before relying on reconstructed pixels.
"""
from pathlib import Path
import re
import sys
import numpy as np
from PIL import Image


def decode_row(payload, seed):
    row = bytearray(seed)
    width = len(seed) // 3
    pos = 0
    x = 0
    cached = (255, 255, 254)

    def take():
        nonlocal pos
        if pos >= len(payload):
            raise ValueError('truncated compressed row')
        v = payload[pos]
        pos += 1
        return v

    def extend():
        n = 0
        while True:
            v = take()
            n += v
            if v != 255:
                return n

    def pixel(at):
        a = take()
        if a & 128:
            v = (a << 8) | take()
            dr, dg, db = ((v >> 10) & 31), ((v >> 5) & 31), (v & 31)
            dr -= 32 if dr & 16 else 0
            dg -= 32 if dg & 16 else 0
            db -= 32 if db & 16 else 0
            old = seed[3*at:3*at+3]
            values = (old[0]+dr, old[1]+dg, (old[2] & 254)+2*db)
            if not all(0 <= n <= 255 for n in values):
                raise ValueError(('invalid delta', at, values))
            return values
        v = ((a << 16) | (take() << 8) | take()) << 1
        return ((v >> 16) & 255, (v >> 8) & 255, v & 255)

    while pos < len(payload):
        command = take()
        rle = bool(command & 128)
        source = (command >> 5) & 3
        offset = (command >> 3) & 3
        if offset == 3:
            offset += extend()
        x += offset
        if x >= width:
            raise ValueError(('offset past row', x, width))
        count = (command & 7) + (2 if rle else 1)
        if source == 0:
            color = pixel(x)
            cached = color
        elif source == 1:
            if x == 0:
                raise ValueError('west pixel before start')
            color = tuple(row[3*(x-1):3*x])
        elif source == 2:
            if x+1 >= width:
                raise ValueError('northeast pixel past end')
            color = tuple(seed[3*(x+1):3*(x+2)])
            color = (color[0], color[1], color[2] & 254)
        else:
            color = cached
        if rle:
            if count == 9:
                count += extend()
            if x+count > width:
                raise ValueError(('run past end', x, count, width))
            row[3*x:3*(x+count)] = bytes(color)*count
            x += count
        else:
            limit = count
            done = 0
            while done < limit:
                if x >= width:
                    raise ValueError('literal past end')
                if done:
                    color = pixel(x)
                row[3*x:3*x+3] = bytes(color)
                x += 1
                done += 1
                if count == 8 and (done-8) % 255 == 0:
                    extra = take()
                    limit += extra
                    if extra < 255:
                        count = -1
    return row


def decode_file(path, width):
    b = Path(path).read_bytes()
    start = b.index(b'@PJL ENTER LANGUAGE=PCL3GUI')
    i = b.index(b'\x1b', start)
    seed = bytearray(b'\xff'*width*3)
    rows = []
    group = None
    stats = {'rows': 0, 'blocks': 0, 'empty_moves': 0, 'commands': []}
    while i < len(b):
        if b.startswith(b'\x1b%-12345X', i):
            break
        if b[i] == 27:
            i += 1
            if b[i:i+2] in (b'*g', b'*r', b'*b', b'*o', b'&u'):
                group = b[i:i+2]
                i += 2
            else:
                raise ValueError(('unknown escape', i, b[i:i+30]))
        m = re.match(rb'([+-]?\d*)([A-Za-z])', b[i:])
        if not m:
            raise ValueError(('bad command', i, b[i:i+30]))
        n = int(m[1] or b'0')
        terminator = chr(m[2][0])
        i += m.end()
        if group == b'*g' and terminator == 'W':
            config = b[i:i+n]
            i += n
            assert len(config) == 12 and config[0] == 6 and config[8] == 10, config
            stats['configuration'] = list(config)
            seed[:] = b'\xff'*len(seed)
            stats['blocks'] += 1
        elif group == b'*b' and terminator.lower() == 'w':
            payload = b[i:i+n]
            if len(payload) != n:
                raise ValueError('truncated transfer')
            i += n
            seed = decode_row(payload, seed)
            rows.append(bytes(seed))
            stats['rows'] += 1
        elif group == b'*b' and terminator.lower() == 'y':
            if n:
                rows.extend([b'\xff'*len(seed)]*n)
                stats['empty_moves'] += n
                seed[:] = b'\xff'*len(seed)
        else:
            stats['commands'].append((group.decode(), n, terminator))
        if terminator.isupper():
            group = None
    if not rows:
        raise ValueError('no decoded rows')
    img = Image.frombytes('RGB', (width, len(rows)), b''.join(rows))
    return img, stats


if __name__ == '__main__':
    import json
    img, stats = decode_file(sys.argv[1], int(sys.argv[2]))
    out = Path(sys.argv[3])
    img.save(out)
    img.thumbnail((1800, 1800))
    img.save(out.with_name(out.stem+'-preview.png'))
    print(json.dumps(stats, ensure_ascii=False))
