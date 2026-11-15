"""Build an isolated copy of the complete A04 Setup-head check.

Requires the pinned stock worker supplied by the caller. The copy performs
the original mechanical head query and accounting. Only its final predicate
accepts the observed mask 10, in the real Setup state35 and worker request6. All other
cases retain the original bit-0 decision. No stock code or IDS state is
written, and the tube-purge worker/FSM is not started. This is a head-check
experiment, not a physical replacement for the air path in Setup heads.
"""
import hashlib
import struct

from ram_rollback_program import Code, checked_workspace

WORKER_ADDRESS = 0xa00f1710
WORKER_BYTES = 160
WORKER_SHA256 = 'f9f7e184879599ade801e21a5a2c606c482368d4374519db3e3f348790203596'
BLOB_BYTES = 256
IDS_STATE = 0xa039d3e4
IDS_REQUEST = 0xa039d3b0
CALLBACK = 0xa039fbd4


def decision(state, request, callback, mask):
    if any(type(x) is not int or not 0 <= x <= 0xffffffff
           for x in (state, request, callback, mask)):
        raise ValueError('four uint32 values required')
    return 1 if (state, request, mask) == (35, 6, 10) else mask & 1


def hook(workspace):
    checked_workspace(workspace)
    c = Code()
    for address, value in ((IDS_STATE, 35), (IDS_REQUEST, 6)):
        c.emit('2239'); c.long(address)  # D1 is caller-clobbered
        c.emit('0c81'); c.long(value)
        c.bne('stock_bit')
    c.compare_d0(10)
    c.branch('6700', 'accept')
    c.mark('stock_bit')
    c.emit('08000000')
    c.branch('6700', 'reject')
    c.mark('accept')
    c.emit('4ef9'); c.long(workspace + 140)
    c.mark('reject')
    c.emit('4ef9'); c.long(workspace + 144)
    return c.finish()


def build(workspace, stock_worker):
    checked_workspace(workspace)
    if (not isinstance(stock_worker, bytes) or len(stock_worker) != WORKER_BYTES
            or hashlib.sha256(stock_worker).hexdigest() != WORKER_SHA256):
        raise ValueError('require the pinned complete A04 head-check worker')
    if stock_worker[132:140] != bytes.fromhex('508f080000006704'):
        raise ValueError('stock predicate boundary differs')
    copied = bytearray(stock_worker)
    copied[132:140] = bytes.fromhex('508f4ef9') + struct.pack('>I', workspace + WORKER_BYTES)
    h = hook(workspace)
    if len(h) > BLOB_BYTES - WORKER_BYTES:
        raise ValueError('hook leaves fixed construction')
    blob = bytes(copied) + h + bytes(BLOB_BYTES - WORKER_BYTES - len(h))
    return {'workspace': workspace, 'worker_code': bytes(copied),
            'hook': workspace + WORKER_BYTES, 'hook_code': h, 'blob': blob,
            'writes_stock_code': False, 'writes_IDS_state': False,
            'starts_priming_FSM': False}
