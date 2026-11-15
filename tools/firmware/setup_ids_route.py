"""Offline one-shot IDS case adapter for the A04 Setup-worker clone.

This builds bytes only. There is deliberately no USB access, arming function,
allocator or dispatcher call. A future live coordinator would have to prove
ownership, idle/real-FSM context, cache visibility, cancellation and rollback.
Restoring the table on entry does not cancel a blocked mechanical worker and
does not permit freeing its allocation before its return.
"""
from ram_rollback_program import Code, checked_workspace
from setup_worker_clone import build as build_worker, IDS_STATE, IDS_REQUEST

CASE_SLOT = 0xa00f1270
STOCK_CASE = 0xa00f12c4
DISPATCH_CONTINUE = 0xa00f12ea
ROUTE_OFFSET = 256
RECEIPT_OFFSET = 512
BLOB_BYTES = 544


def route_code(workspace):
    checked_workspace(workspace)
    route = workspace + ROUTE_OFFSET
    receipt = workspace + RECEIPT_OFFSET
    c = Code()
    c.read(CASE_SLOT)
    c.compare_d0(route)
    c.bne('foreign_slot')
    # Restore this data pointer before any potentially blocking native call.
    # Use D0: immediate-to-absolute MOVE is not supported by ColdFire.
    c.store(STOCK_CASE, CASE_SLOT)
    c.store(1, receipt)  # entered, slot restored, worker not yet returned
    for address, offset in ((IDS_STATE, 8), (IDS_REQUEST, 12)):
        c.read(address); c.store_d0(receipt + offset)
    c.emit('42a7')
    c.call(workspace)
    c.emit('588f')
    c.store_d0(receipt + 4)
    c.emit('2c00')  # D6 is the stock case result consumed by IDS
    c.store(2, receipt)
    c.emit('4ef9'); c.long(DISPATCH_CONTINUE)
    c.mark('foreign_slot')
    # A fetched old pointer must not overwrite a new owner's table value.
    # Continue through the original case, with no override and no receipt
    # completion claim. Stock remains responsible for its normal result.
    c.store(3, receipt)
    c.emit('4ef9'); c.long(STOCK_CASE)
    code = c.finish()
    if ROUTE_OFFSET + len(code) > RECEIPT_OFFSET:
        raise ValueError('route overlaps its receipt')
    return code


def build(workspace, stock_worker):
    checked_workspace(workspace)
    worker = build_worker(workspace, stock_worker)
    route = workspace + ROUTE_OFFSET
    receipt = workspace + RECEIPT_OFFSET
    code = route_code(workspace)
    blob = bytearray(BLOB_BYTES)
    blob[:len(worker['blob'])] = worker['blob']
    blob[ROUTE_OFFSET:ROUTE_OFFSET + len(code)] = code
    return {**worker, 'blob': bytes(blob), 'route': route, 'route_code': code,
            'receipt': receipt, 'case_slot': CASE_SLOT, 'original_case': STOCK_CASE,
            'writes_stock_jump_table_if_armed': True,
            'restores_slot_before_worker': True, 'live_coordinator_available': False}
