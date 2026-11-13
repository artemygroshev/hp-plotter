"""Decode bounded A.04.02 VxWorks task records; no device access.

Derived from taskIdListGet/taskInfoGet and the ready/suspended predicates in
the pinned engine image. Saved SP and errno are not a fault PC or HP error.
"""
import struct

TASK_IDS_GET = 0xa005d630
TASK_INFO_GET = 0xa0063de0
TASK_DESCRIPTOR_BYTES = 64
CAPACITY = 64


def task_pointer(value):
    return type(value) is int and value % 4 == 0 and 0xa044d000 <= value < 0xa2000000 - 512


def decode_ids(data, count):
    if type(count) is not int or not 1 <= count < CAPACITY or len(data) != count * 4:
        raise ValueError('task list is empty, capped, or incomplete')
    ids = struct.unpack('>' + str(count) + 'I', data)
    if len(set(ids)) != count or not all(task_pointer(value) for value in ids):
        raise ValueError('task pointers are invalid or duplicated')
    return ids


def decode_descriptor(data, expected_tid):
    if len(data) != TASK_DESCRIPTOR_BYTES or not task_pointer(expected_tid):
        raise ValueError('require a complete descriptor and a validated task ID')
    values = struct.unpack('>16I', data)
    tid, name, priority, status, options, entry, saved_sp = values[:7]
    if (tid != expected_tid or not 0xa0001000 <= name <= 0xa2000000 - 16
            or priority > 255 or status > 15 or not 0xa0001000 <= entry < 0xa044d000):
        raise ValueError('task descriptor differs from the reviewed layout')
    return {'tid': hex(tid), 'name_pointer': hex(name), 'priority': priority,
            'status_raw': status, 'suspended': bool(status & 1), 'ready': status == 0,
            'entry': hex(entry), 'saved_sp': hex(saved_sp),
            'errno_raw': hex(values[14]), 'delay_raw': values[15]}
