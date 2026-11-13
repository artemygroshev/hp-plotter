"""Offline builder for a guarded A.04.02 Setup-tail decision round trip.

The wrapper enters after the unsafe worker's mechanical dispatch and status
refresh. It uses the cached AND mask. The false-path UI callback must be null
throughout the IRQ-locked transaction. This never starts the Setup procedure.
"""
import hashlib

from ram_rollback_program import (Code, checked_workspace, validate_instruction_subset,
                                  IRQ_LOCK, IRQ_UNLOCK, CACHE_CLEAR, PRODUCTION_WORD, MAGIC)

CALLBACK_HANDLE = 0xa039fbd4
CACHED_AND = 0xa039fca4
TAIL_ENTRY = 0xa00f1796
EXPECTED_AND = 10
ORIGINAL = 0x00006704
CHANGED = 0x00004e71
SESSION_QUERY_LIMIT = 87
# Five 128-byte read-back chunks, cache, native call, receipt, stock word,
# free and two final identity queries. None may be consumed by copy loading.
FINISH_QUERIES = 12


def build(workspace):
    checked_workspace(workspace)
    wrapper = workspace + 512
    receipt = workspace + 536
    c = Code()
    c.emit('4e5600002f022f032f042f052f062f0a7400')
    c.emit('247c'); c.long(PRODUCTION_WORD)
    c.emit('283c'); c.long(ORIGINAL)
    c.emit('2a3c'); c.long(CHANGED)
    c.store(MAGIC, receipt)
    for offset in range(4, 40, 4):
        c.store(0, receipt + offset)
    c.call(IRQ_LOCK); c.emit('2600')
    for address, expected in ((0xa039d3e4, 1), (0xa039d3b0, 0),
                              (CALLBACK_HANDLE, 0), (CACHED_AND, EXPECTED_AND)):
        c.read(address); c.compare_d0(expected); c.bne('finish')
    c.store_d0(receipt + 24)
    c.emit('2012'); c.store_d0(receipt + 12)
    c.emit('b084'); c.bne('finish')
    c.call(wrapper); c.store_d0(receipt + 28)
    c.compare_d0(0); c.bne('finish')
    c.emit('0082'); c.long(4)
    c.store(1, receipt + 4)
    c.emit('2485')
    c.store(2, receipt + 4)
    c.emit('487800042f0a42a7'); c.call(CACHE_CLEAR); c.emit('4fef000c')
    c.compare_d0(0); c.bne('restore')
    c.emit('2012'); c.store_d0(receipt + 16)
    c.emit('b085'); c.bne('restore')
    c.call(wrapper); c.store_d0(receipt + 32)
    c.compare_d0(1); c.bne('restore')
    c.emit('0082'); c.long(1)
    c.mark('restore')
    c.store(3, receipt + 4)
    c.emit('2484')
    c.emit('487800042f0a42a7'); c.call(CACHE_CLEAR); c.emit('4fef000c')
    c.compare_d0(0); c.bne('finish')
    c.emit('2012'); c.store_d0(receipt + 20)
    c.emit('b084'); c.bne('finish')
    c.call(wrapper); c.store_d0(receipt + 36)
    c.compare_d0(0); c.bne('finish')
    c.emit('0082'); c.long(2)
    c.mark('finish')
    c.emit('23c2'); c.long(receipt + 8)
    c.store(4, receipt + 4)
    c.emit('2f03'); c.call(IRQ_UNLOCK); c.emit('588f')
    c.emit('2002245f2c1f2a1f281f261f241f4e5e4e75')
    code = c.finish()
    validate_instruction_subset(code)
    if len(code) > 512:
        raise ValueError('transaction overlaps its wrapper')
    # Exactly the frame shape consumed by the stock tail's D7/UNLK/RTS.
    wrapper_code = bytes.fromhex('4e56fffc2d47fffc2039a039fca44ef9a00f1796')
    blob = bytearray(576)
    blob[:len(code)] = code
    blob[512:512 + len(wrapper_code)] = wrapper_code
    return {'workspace': workspace, 'code': code, 'wrapper': wrapper,
            'wrapper_code': wrapper_code, 'receipt': receipt, 'blob': bytes(blob),
            'expected_receipt': (MAGIC, 4, 7, ORIGINAL, CHANGED, ORIGINAL, EXPECTED_AND, 0, 1, 0),
            'entry_skips_mechanical_dispatch': True, 'starts_setup_procedure': False}


def validate_plan(plan, workspace, queries_used):
    program = build(workspace)
    blob = program['blob']
    if (type(queries_used) is not int or not 0 <= queries_used < SESSION_QUERY_LIMIT
            or plan.get('workspace') != workspace
            or plan.get('blob_sha256') != hashlib.sha256(blob).hexdigest()
            or not isinstance(plan.get('copies'), list) or not plan['copies']):
        raise ValueError('copy plan does not describe the fixed tail transaction')
    copy_queries = (len(plan['copies']) + 3) // 4
    if queries_used + copy_queries + FINISH_QUERIES > SESSION_QUERY_LIMIT:
        raise ValueError('copy plan would consume execution or cleanup query budget')
    position = workspace
    for item in plan['copies']:
        if not isinstance(item, list) or len(item) != 3 or any(type(value) is not int for value in item):
            raise ValueError('invalid copy slice')
        source, destination, length = item
        if (not 1 <= length <= 64 or destination != position
                or not 0xa0001000 <= source <= 0xa0380000 - length
                or destination + length > workspace + len(blob)):
            raise ValueError('copy leaves the immutable image or owned construction')
        position += length
    if position != workspace + len(blob):
        raise ValueError('copy plan has incomplete coverage')
    return program, {'copy_queries': copy_queries, 'finish_queries_reserved': FINISH_QUERIES,
                     'maximum_total_queries': queries_used + copy_queries + FINISH_QUERIES}
