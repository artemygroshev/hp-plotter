"""Fixed task-inspection transport, without the long osTaskShow text output.

No CLI, task deletion, task suspension or guard bypass. The caller must own
the shared lock/guard, verify live helper code and retain allocation/phase
records. Task data are read into a newly acknowledged allocation only.
"""
from quiet_end_reads import QuietEndReadSession
from ram_rollback_probe import frame, parse
from task_layout_a04 import CAPACITY, TASK_IDS_GET, TASK_INFO_GET, task_pointer
import probe_printer as probe

ALLOCATION_BYTES = 4608
DESCRIPTORS_OFFSET = 256


def owned_pointer(value):
    return type(value) is int and value % 4 == 0 and 0xa044d000 <= value <= 0xa2000000 - ALLOCATION_BYTES


class TaskReadSession(QuietEndReadSession):
    def __init__(self, *args, **kwargs):
        if kwargs.get('comment_bytes', 63) != 63:
            raise ValueError('structured task reads require COMMENT63')
        kwargs['comment_bytes'] = 63
        super().__init__(*args, **kwargs)
        self.workspace = None
        self.task_ids = ()
        self.name_addresses = set()
        self.plans = {}

    def schedule(self, stage):
        if stage in self.plans:
            raise RuntimeError('one attempt per fixed stage')
        pointer = self.workspace
        if stage == 'tasks_allocate':
            if pointer is not None:
                raise ValueError('one allocation only')
            commands = ['osMemAlloc 4608']
        else:
            if not owned_pointer(pointer):
                raise ValueError('a newly acknowledged allocation is required')
            if stage in ('tasks_ids_before', 'tasks_ids_after'):
                commands = [f'osFuncCall {hex(TASK_IDS_GET)} 2 {hex(pointer)} {CAPACITY}']
            elif stage.startswith('tasks_info_'):
                index = int(stage.removeprefix('tasks_info_'))
                if (not 0 <= index < len(self.task_ids) < CAPACITY or index % 4
                        or not all(task_pointer(tid) for tid in self.task_ids)):
                    raise ValueError('descriptor group is outside the verified task list')
                commands = [f'osFuncCall {hex(TASK_INFO_GET)} 2 {hex(tid)} '
                            f'{hex(pointer + DESCRIPTORS_OFFSET + (index + offset) * 64)}'
                            for offset, tid in enumerate(self.task_ids[index:index + 4])]
            elif stage == 'tasks_free':
                commands = ['osMemFree ' + hex(pointer)]
            else:
                raise ValueError('unknown task-inspection stage')
        self.plans[stage] = commands

    def command_payload(self, kind, nonce, memory=None):
        if kind == 'runtime_mem' and memory is not None and owned_pointer(self.workspace):
            address, length = memory
            if (type(address) is int and type(length) is int and 1 <= length <= 128
                    and (self.workspace <= address <= self.workspace + ALLOCATION_BYTES - length
                         or (address in self.name_addresses and length == 16
                             and 0xa0001000 <= address <= 0xa2000000 - 16))):
                script = (f'puts B{nonce}\nosMemDump {hex(address)} {length}\n'
                          f'puts E{nonce}\nexit\n').encode()
                prefix = probe.UEL + b'@PJL ENTER LANGUAGE=TCLWARE\r\n' + script
                tail = b'\n' + probe.UEL + b'\r\n'
                padding = 129 - len(prefix) - len(tail)
                if padding < 1:
                    raise ValueError('owned read exceeds the fixed frame')
                return prefix + b'#' + b' ' * (padding - 1) + tail
        if kind not in self.plans:
            return super().command_payload(kind, nonce, memory)
        if memory is not None or any(query['kind'] == kind for query in self.queries):
            raise RuntimeError('no native operation replay')
        return frame(self.plans[kind], nonce)

    def phase_limit(self, kind):
        return 20 if kind in self.plans else super().phase_limit(kind)

    def validate_reply(self, kind, nonce, raw, memory, report):
        if kind not in self.plans:
            return super().validate_reply(kind, nonce, raw, memory, report)
        report['native_results'] = parse(raw, nonce, len(self.plans[kind]))
        if kind == 'tasks_free':
            if report['native_results'] != [0]:
                raise RuntimeError('allocation free was not acknowledged')
            self.workspace = None
            self.task_ids = ()
            self.name_addresses.clear()
