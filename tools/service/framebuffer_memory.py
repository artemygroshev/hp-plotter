"""Decode strictly addressed native memory-dump replies; entirely offline.

This module never selects a live address or contacts a device. Reading a
dynamic pointer requires separate, verified firmware and pointer provenance.
"""
import re
import struct
import zlib


def native_png(data,scale=1):
    """Encode complete native pixels without requiring Pillow on a small SBC."""
    if len(data)!=1024 or type(scale) is not int or not 1<=scale<=8:
        raise ValueError('a full LCD buffer and integer scale 1..8 are required')
    rows=[]
    for y in range(64):
        row=bytearray()
        for x in range(128):
            word=struct.unpack_from('>I',data,4*((x//32)*64+y))[0]
            value=0 if word & (1 << (31-x%32)) else 255
            row.extend(bytes([value])*scale)
        rows.extend([b'\0'+row]*scale)
    def chunk(kind,payload):
        return struct.pack('>I',len(payload))+kind+payload+struct.pack('>I',zlib.crc32(kind+payload)&0xffffffff)
    return (b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',128*scale,64*scale,8,0,0,0,0))
            +chunk(b'IDAT',zlib.compress(b''.join(rows)))+chunk(b'IEND',b''))


def extract_tagged_value(raw, nonce, tag='P', separator=' '):
    if not re.fullmatch(r'[a-f0-9]{6}', nonce) or not re.fullmatch(r'[A-Z]', tag) or separator not in (' ', '_'):
        raise ValueError('invalid value correlation tag')
    pattern = (rb'(?:B'+nonce.encode()+rb'\n)?'+tag.encode()+nonce.encode()+
               re.escape(separator.encode())+rb'([^\r\n]+)\nE'+nonce.encode()+rb'\n')
    match = re.fullmatch(pattern, raw)
    if not match:
        raise ValueError('value is not bound to its unique fresh tag and final marker')
    return match[1].decode('ascii')


def extract_addressed_reply(raw, nonce, address, length):
    """Native C FILE output can replace Tcl's initial marker on this device.

    Require the unique fresh final marker, every requested byte at its printed
    address, and no other data. No byte insertion, deletion or padding is used.
    A single read must be outstanding and previous output drained by caller.
    """
    if not re.fullmatch(r'[a-f0-9]{6}', nonce):
        raise ValueError('invalid correlation nonce')
    begin = b'B'+nonce.encode()+b'\n'
    end = b'E'+nonce.encode()+b'\n'
    if raw.count(end) != 1 or not raw.endswith(b'\n'+end):
        raise ValueError('unique final nonce is absent or has trailing data')
    body = raw[:-len(end)]
    begin_present = body.startswith(begin)
    if begin_present:
        body = body[len(begin):]
    data = parse_dump(body, address, length)
    return data, {'native_address_coverage_verified': True,
                  'fresh_end_nonce_verified': True,
                  'begin_marker_verified': begin_present,
                  'requested_bytes': length, 'bytes_modified': False}


def parse_dump(body, address, length):
    if not 1 <= length <= 128 or not 0 <= address <= 0xffffffff-length:
        raise ValueError('dump span outside one short inspection')
    rows = body.decode('ascii').splitlines()
    values = {}
    row_addresses = set()
    for line in rows:
        if not line:
            continue
        match = re.fullmatch(r'([a-fA-F0-9]{8}):  (.{48})', line)
        if not match:
            raise ValueError('unexpected native dump row')
        start = int(match[1], 16)
        if start % 16 or start in row_addresses:
            raise ValueError('unaligned or duplicate row')
        row_addresses.add(start)
        for offset in range(16):
            cell = match[2][3*offset:3*offset+3]
            if cell == '   ':
                continue
            if not re.fullmatch(r'[a-fA-F0-9]{2} ', cell):
                raise ValueError('invalid byte cell')
            location = start+offset
            if not address <= location < address+length:
                raise ValueError('populated byte outside requested span')
            values[location] = int(cell[:2], 16)
    expected_rows = set(range(address & ~15, (address+length+15) & ~15, 16))
    if row_addresses != expected_rows or len(values) != length:
        raise ValueError('missing or extra addressed bytes')
    return bytes(values[x] for x in range(address, address+length))


def decode_native_bitmap(data):
    """A04 accessor: 4 columns of 64 big-endian 32-bit words, top row first."""
    if len(data) != 1024:
        raise ValueError('the complete 128 by 64 buffer is required')
    from PIL import Image
    image = Image.new('RGB', (128, 64), 'white')
    pixels = image.load()
    for column in range(4):
        for row in range(64):
            word, = struct.unpack_from('>I', data, 4*(column*64+row))
            for bit in range(32):
                pixels[column*32+bit, row] = (0, 0, 0) if word & (1 << (31-bit)) else (255, 255, 255)
    return image
