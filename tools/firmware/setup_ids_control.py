"""Build short IRQ-protected arm/disarm transactions for the IDS route.

Offline construction only. This neither enters the Setup FSM nor submits a
worker. A future host coordinator still needs fresh device/context proofs,
exclusive ownership, a verified allocation/readback/cache and exact replies.
The transaction does not cancel mechanics or cover CPU faults. Its numeric
workspace check is not evidence that an allocation is actually owned.
"""
from ram_rollback_program import Code, checked_workspace, IRQ_LOCK, IRQ_UNLOCK
from setup_ids_route import (build as build_route, route_code, CASE_SLOT, STOCK_CASE,
                             ROUTE_OFFSET, RECEIPT_OFFSET)
from setup_worker_clone import IDS_STATE, IDS_REQUEST

CONTROL_OFFSET = 544
CONTROL_RECEIPT_OFFSET = 384
CONTROL_RECEIPT_BYTES = 36
CACHED_HEAD_AND = 0xa039fca4
MAGIC = 0x48504944
BLOB_BYTES = 1024
WAIT_STATES = (29, 31)  # real Setup window-open/window-closed waiting states


def control_code(workspace):
    checked_workspace(workspace)
    receipt = workspace + CONTROL_RECEIPT_OFFSET
    phase = workspace + RECEIPT_OFFSET
    route = workspace + ROUTE_OFFSET
    c = Code()
    c.emit('4e5600002f022f032f04242e00087800')
    c.store(MAGIC, receipt)
    c.emit('23c2'); c.long(receipt + 8)
    c.call(IRQ_LOCK); c.emit('2600')
    for address, offset in ((CASE_SLOT, 12), (IDS_STATE, 16), (IDS_REQUEST, 20),
                            (phase, 24), (CACHED_HEAD_AND, 28)):
        c.read(address); c.store_d0(receipt + offset)
    c.emit('2002'); c.compare_d0(1); c.branch('6200', 'finish')
    # Both operations require no active IDS request. In particular a fetched
    # route must not be declared removable while request6 is still in flight.
    c.read(IDS_REQUEST); c.compare_d0(0); c.bne('finish')
    c.emit('2002'); c.compare_d0(1); c.branch('6700', 'disarm')
    c.read(IDS_STATE); c.compare_d0(WAIT_STATES[0]); c.branch('6700', 'waiting')
    c.compare_d0(WAIT_STATES[1]); c.bne('finish')
    c.mark('waiting')
    for address, value in ((phase, 0), (CACHED_HEAD_AND, 10), (CASE_SLOT, STOCK_CASE)):
        c.read(address); c.compare_d0(value); c.bne('finish')
    c.store(route, CASE_SLOT)
    c.emit('7801'); c.branch('6000', 'finish')
    c.mark('disarm')
    c.read(phase); c.compare_d0(0); c.branch('6700', 'not_entered')
    c.compare_d0(2); c.bne('finish')
    # A returned worker must already have restored the slot. Other values are
    # inconsistent; never use the host timeout as permission to repair/free.
    c.read(CASE_SLOT); c.compare_d0(STOCK_CASE); c.bne('finish')
    c.emit('7802'); c.branch('6000', 'finish')
    c.mark('not_entered')
    c.read(CASE_SLOT); c.compare_d0(STOCK_CASE); c.branch('6700', 'disarmed')
    c.compare_d0(route); c.bne('finish')
    c.store(STOCK_CASE, CASE_SLOT)
    c.mark('disarmed'); c.emit('7802')
    c.mark('finish')
    c.emit('23c4'); c.long(receipt + 4)
    c.read(CASE_SLOT); c.store_d0(receipt + 32)
    c.emit('2f03'); c.call(IRQ_UNLOCK); c.emit('588f')
    c.emit('2004281f261f241f4e5e4e75')
    code = c.finish()
    if CONTROL_OFFSET + len(code) > BLOB_BYTES:
        raise ValueError('control code exceeds its owned allocation')
    if ROUTE_OFFSET + len(route_code(workspace)) > CONTROL_RECEIPT_OFFSET:
        raise ValueError('route overlaps the independent control receipt')
    return code


def build(workspace, stock_worker):
    route = build_route(workspace, stock_worker)
    code = control_code(workspace)
    blob = bytearray(BLOB_BYTES)
    blob[:len(route['blob'])] = route['blob']
    blob[CONTROL_OFFSET:CONTROL_OFFSET + len(code)] = code
    return {**route, 'blob': bytes(blob), 'control': workspace + CONTROL_OFFSET,
            'control_code': code, 'control_receipt': workspace + CONTROL_RECEIPT_OFFSET,
            'control_receipt_bytes': CONTROL_RECEIPT_BYTES, 'arm_mode': 0, 'disarm_mode': 1,
            'arm_states': WAIT_STATES, 'starts_priming_FSM': False,
            'live_coordinator_available': False}
