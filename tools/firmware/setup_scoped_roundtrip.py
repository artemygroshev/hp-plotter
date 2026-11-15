"""Offline construction of one state-scoped Setup recognition experiment.

It temporarily changes the real tail and the IDS state under one IRQ lock,
calls only the tail after mechanical dispatch, and restores both before
unlocking. It never runs the IDS worker, a pump, or an installation procedure.
There is no CLI or USB executor. CPU faults are not covered by rollback.
"""
import hashlib
import struct

from ram_rollback_program import (Code, checked_workspace, validate_instruction_subset,
                                  IRQ_LOCK, IRQ_UNLOCK, MAGIC)
from setup_tail_roundtrip import CALLBACK_HANDLE, CACHED_AND, TAIL_ENTRY

PATCH_ADDRESS = 0xa00f1794
IDS_STATE = 0xa039d3e4
IDS_REQUEST = 0xa039d3b0
ORIGINAL_WORDS = (0x508f0800, 0x00006704)
SCOPED_JUMP_WORD = 0x508f4ef9
RECEIPT_WORDS = 19
FINISH_QUERIES = 15
SESSION_QUERY_LIMIT = 87


def scoped_decision(state, mask):
    """Only the observed normal-head AND in Setup state receives an override."""
    if any(type(v) is not int or not 0 <= v <= 0xffffffff for v in (state, mask)):
        raise ValueError('require unsigned 32-bit state and AND mask')
    return 1 if state == 35 and mask == 10 else mask & 1


def build_hook():
    c = Code()
    c.emit('2239'); c.long(IDS_STATE)       # volatile D1, actual IDS state
    c.emit('0c81'); c.long(35)
    c.bne('stock_bit')
    c.compare_d0(10)
    c.bne('stock_bit')
    c.emit('4ef9'); c.long(0xa00f179c)      # stock true path
    c.mark('stock_bit')
    c.emit('08000000')                    # original bit-0 predicate
    c.branch('6700', 'stock_false')
    c.emit('4ef9'); c.long(0xa00f179c)
    c.mark('stock_false')
    c.emit('4ef9'); c.long(0xa00f17a0)      # stock false/UI path
    return c.finish()


def build(workspace):
    checked_workspace(workspace)
    wrapper, hook, receipt = workspace + 640, workspace + 672, workspace + 736
    c = Code()
    scope_moveq = []
    c.emit('4e5600002f022f037400')
    c.store(MAGIC, receipt)
    c.store(0, receipt + 4)
    c.store(0, receipt + 8)
    c.call(IRQ_LOCK); c.emit('2600')
    for address, expected, offset in ((IDS_STATE, 1, 36), (IDS_REQUEST, 0, 68),
                                     (CALLBACK_HANDLE, 0, 72), (CACHED_AND, 10, 44)):
        c.read(address); c.store_d0(receipt + offset)
        c.compare_d0(expected); c.bne('finish')
    for index, expected in enumerate(ORIGINAL_WORDS):
        c.read(PATCH_ADDRESS + index * 4); c.store_d0(receipt + 12 + index * 4)
        c.compare_d0(expected); c.bne('finish')

    def result(offset, expected, failure):
        c.call(wrapper); c.store_d0(receipt + offset)
        c.compare_d0(expected); c.bne(failure)

    def set_state(value):
        if value not in (1, 26, 35):
            raise ValueError('only the three fixed scoped-test states are allowed')
        if value in (26, 35):
            scope_moveq.append((len(c.data), value))
        c.store(value, IDS_STATE)

    result(48, 0, 'finish')
    c.emit('0082'); c.long(4)
    c.store(1, receipt + 4)
    for index, value in enumerate((SCOPED_JUMP_WORD, hook)):
        c.store(value, PATCH_ADDRESS + index * 4)
    c.store(2, receipt + 4)
    c.flush(PATCH_ADDRESS, 8); c.compare_d0(0); c.bne('restore')
    for index, expected in enumerate((SCOPED_JUMP_WORD, hook)):
        c.read(PATCH_ADDRESS + index * 4); c.store_d0(receipt + 20 + index * 4)
        c.compare_d0(expected); c.bne('restore')
    result(52, 0, 'restore')               # actual idle state: no override
    set_state(35)
    result(56, 1, 'restore')               # actual Setup state, same mask
    set_state(26)
    result(60, 0, 'restore')               # removal stage: stock behavior
    c.emit('0082'); c.long(1)
    c.mark('restore')
    c.store(3, receipt + 4)
    set_state(1)
    for index, value in enumerate(ORIGINAL_WORDS):
        c.store(value, PATCH_ADDRESS + index * 4)
    c.flush(PATCH_ADDRESS, 8); c.compare_d0(0); c.bne('finish')
    for index, expected in enumerate(ORIGINAL_WORDS):
        c.read(PATCH_ADDRESS + index * 4); c.store_d0(receipt + 28 + index * 4)
        c.compare_d0(expected); c.bne('finish')
    c.read(IDS_STATE); c.store_d0(receipt + 40)
    c.compare_d0(1); c.bne('finish')
    result(64, 0, 'finish')
    c.emit('0082'); c.long(2)
    c.mark('finish')
    c.emit('23c2'); c.long(receipt + 8)
    c.store(4, receipt + 4)
    c.emit('2f03'); c.call(IRQ_UNLOCK); c.emit('588f')
    c.emit('2002261f241f4e5e4e75')
    code = c.finish()
    # Reuse the old boundary validator with two reviewed MOVEQ constants.
    # Replace only generator-recorded instruction positions, never bytes
    # found by searching arbitrary immediates or addresses.
    checked = bytearray(code)
    for offset, value in scope_moveq:
        if code[offset:offset + 2] != struct.pack('>H', 0x7000 | value):
            raise ValueError('scoped MOVEQ position differs')
        checked[offset:offset + 2] = bytes.fromhex('7000')
    validate_instruction_subset(bytes(checked))
    wrapper_code = bytes.fromhex('4e56fffc2d47fffc2039a039fca44ef9a00f1796')
    hook_code = build_hook()
    if len(code) > 640 or len(wrapper_code) > 32 or len(hook_code) > 64:
        raise ValueError('code parts overlap their fixed owned layout')
    blob = bytearray(832)
    blob[:len(code)] = code
    blob[640:640 + len(wrapper_code)] = wrapper_code
    blob[672:672 + len(hook_code)] = hook_code
    return {'workspace': workspace, 'code': code, 'wrapper': wrapper,
            'wrapper_code': wrapper_code, 'hook': hook, 'hook_code': hook_code,
            'receipt': receipt, 'blob': bytes(blob),
            'expected_receipt': (MAGIC, 4, 7, *ORIGINAL_WORDS,
                                 SCOPED_JUMP_WORD, hook, *ORIGINAL_WORDS,
                                 1, 1, 10, 0, 0, 1, 0, 0, 0, 0),
            'temporarily_changes_IDS_state': True,
            'starts_setup_procedure': False, 'persistent_override': False}


def validate_plan(plan, workspace, queries_used):
    program = build(workspace)
    if (type(queries_used) is not int or not 0 <= queries_used < SESSION_QUERY_LIMIT
            or plan.get('workspace') != workspace
            or plan.get('blob_sha256') != hashlib.sha256(program['blob']).hexdigest()
            or not isinstance(plan.get('copies'), list) or not plan['copies']):
        raise ValueError('plan does not describe the fixed scoped transaction')
    copy_queries = (len(plan['copies']) + 3) // 4
    if queries_used + copy_queries + FINISH_QUERIES > SESSION_QUERY_LIMIT:
        raise ValueError('copy plan consumes the execution/restore/free budget')
    position = workspace
    for row in plan['copies']:
        if not isinstance(row, list) or len(row) != 3 or any(type(x) is not int for x in row):
            raise ValueError('invalid copy slice')
        source, destination, size = row
        if (not 1 <= size <= 64 or destination != position
                or not 0xa0001000 <= source <= 0xa0380000 - size
                or destination + size > workspace + len(program['blob'])):
            raise ValueError('copy leaves immutable image or owned construction')
        position += size
    if position != workspace + len(program['blob']):
        raise ValueError('incomplete copy coverage')
    return program, {'copy_queries': copy_queries, 'finish_queries_reserved': FINISH_QUERIES,
                     'maximum_total_queries': queries_used + copy_queries + FINISH_QUERIES}
