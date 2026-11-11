"""Build a fixed A04 RAM transaction that restores its word before returning.

Offline research only; hardware execution has not been accepted. The intended
transaction restores its selected word before returning. This is not a
persistent Setup override or a guarantee against CPU faults.
"""
import struct

COPY = 0xa0010770
CACHE_CLEAR = 0xa0010a94
IRQ_LOCK = 0xa0010e82
IRQ_UNLOCK = 0xa0010e9a
ALLOCATION_BYTES = 1024
PRODUCTION_WORD = 0xa00f1798
MAGIC = 0x48505242


class Code:
    def __init__(self):
        self.data = bytearray()
        self.labels = {}
        self.fixups = []

    def emit(self, value):
        self.data.extend(bytes.fromhex(value))

    def long(self, value):
        self.data.extend(struct.pack('>I', value))

    def mark(self, label):
        self.labels[label] = len(self.data)

    def branch(self, opcode, label):
        offset = len(self.data)
        self.emit(opcode + '0000')
        self.fixups.append((offset, label))

    def bne(self, label):
        self.branch('6600', label)

    def store(self, value, address):
        # ColdFire does not support MOVE.L #immediate,absolute.l. A generic
        # M68K emulator accepts that ten-byte instruction; use D0 explicitly.
        self.emit('203c'); self.long(value)
        self.store_d0(address)

    def read(self, address):
        self.emit('2039'); self.long(address)

    def store_d0(self, address):
        self.emit('23c0'); self.long(address)

    def compare_d0(self, value):
        self.emit('0c80'); self.long(value)

    def call(self, address):
        self.emit('4eb9'); self.long(address)

    def flush(self, address, length=4):
        self.emit('4878'); self.data.extend(struct.pack('>H', length))
        self.emit('4879'); self.long(address)
        self.emit('42a7')
        self.call(CACHE_CLEAR)
        self.emit('4fef000c')

    def finish(self):
        for offset, label in self.fixups:
            struct.pack_into('>h', self.data, offset + 2, self.labels[label] - offset - 2)
        return bytes(self.data)


def checked_workspace(address):
    if (type(address) is not int or address % 4
            or not 0xa044d000 <= address <= 0xa2000000 - ALLOCATION_BYTES):
        raise ValueError('workspace must be a newly owned, aligned A04 heap allocation')
    return address


def validate_instruction_subset(data):
    """Reject everything outside this builder's reviewed ColdFire ISA_A subset.

    This deliberately is not a general 68K/ColdFire decoder. It checks complete
    instruction boundaries and branch destinations, independent of Unicorn.
    See NXP CFPRM rev.3, integer instruction definitions, especially MOVE 4-48.
    Passing this check does not establish hardware/cache/exception behavior.
    """
    sizes = {}
    for word in ('7400', '4a86', '2600', '2012', 'b084', '4e92', '2485',
                 'b085', '2484', '2f03', '588f', '2002', '245f', '2c1f',
                 '2a1f', '281f', '261f', '241f', '4e5e', '4e75', '2f02',
                 '2f04', '2f05', '2f06', '2f0a', '42a7'):
        sizes[int(word, 16)] = 2
    for word in ('4e56', '2c2e', '6200', '6600', '6700', '4878', '4fef'):
        sizes[int(word, 16)] = 4
    for word in ('0c86', '247c', '283c', '2a3c', '203c', '23c0', '23c6',
                 '4eb9', '2039', '0c80', '0082', '23c2', '4879'):
        sizes[int(word, 16)] = 6
    offset = 0
    boundaries, branches, instructions = set(), [], []
    while offset < len(data):
        if len(data) - offset < 2:
            raise ValueError('truncated instruction word')
        word, = struct.unpack_from('>H', data, offset)
        size = sizes.get(word)
        if size is None or offset + size > len(data):
            raise ValueError('unsupported or truncated ColdFire subset opcode at %d: %04x' % (offset, word))
        boundaries.add(offset)
        if word in (0x6200, 0x6600, 0x6700):
            displacement, = struct.unpack_from('>h', data, offset + 2)
            branches.append(offset + 2 + displacement)
        instructions.append((offset, size, word))
        offset += size
    if any(target not in boundaries for target in branches):
        raise ValueError('branch does not land on an instruction within the program')
    return instructions


def build(workspace):
    checked_workspace(workspace)
    receipt = workspace + 544
    shadow = workspace + 512
    c = Code()
    c.emit('4e5600002f022f032f042f052f062f0a')
    c.emit('74002c2e00080c8600000001')
    c.branch('6200', 'no_lock_exit')  # only mode 0 or 1
    c.emit('247c'); c.long(shadow)
    c.emit('283c70014e752a3c70024e75')
    c.emit('4a86'); c.branch('6700', 'selected')
    c.emit('247c'); c.long(PRODUCTION_WORD)
    c.emit('283c000067042a3c00004e71')
    c.mark('selected')
    c.store(MAGIC, receipt)
    c.store(0, receipt + 4)
    c.store(0, receipt + 8)
    c.emit('23c6'); c.long(receipt + 24)
    c.call(IRQ_LOCK); c.emit('2600')
    c.emit('4a86'); c.branch('6700', 'guard_done')
    c.read(0xa039d3e4); c.compare_d0(1); c.bne('finish')
    c.read(0xa039d3b0); c.compare_d0(0); c.bne('finish')
    c.mark('guard_done')
    c.emit('2012'); c.store_d0(receipt + 12)
    c.emit('b084'); c.bne('finish')
    c.emit('4a86'); c.bne('baseline_done')
    c.emit('4e92'); c.compare_d0(1); c.bne('finish')
    c.mark('baseline_done')
    c.emit('0082'); c.long(4)
    c.store(1, receipt + 4)
    c.emit('2485')  # one aligned long store to selected word
    c.store(2, receipt + 4)
    c.emit('487800042f0a42a7'); c.call(CACHE_CLEAR); c.emit('4fef000c')
    c.compare_d0(0); c.bne('restore')
    c.emit('2012'); c.store_d0(receipt + 16)
    c.emit('b085'); c.bne('restore')
    c.emit('4a86'); c.bne('changed_call_done')
    c.emit('4e92'); c.compare_d0(2); c.bne('restore')
    c.mark('changed_call_done')
    c.emit('0082'); c.long(1)
    c.mark('restore')
    c.store(3, receipt + 4)
    c.emit('2484')
    c.emit('487800042f0a42a7'); c.call(CACHE_CLEAR); c.emit('4fef000c')
    c.compare_d0(0); c.bne('finish')
    c.emit('2012'); c.store_d0(receipt + 20)
    c.emit('b084'); c.bne('finish')
    c.emit('4a86'); c.bne('restored_call_done')
    c.emit('4e92'); c.compare_d0(1); c.bne('finish')
    c.mark('restored_call_done')
    c.emit('0082'); c.long(2)
    c.mark('finish')
    c.emit('23c2'); c.long(receipt + 8)
    c.store(4, receipt + 4)
    c.emit('2f03'); c.call(IRQ_UNLOCK); c.emit('588f')
    c.mark('no_lock_exit')
    c.emit('2002245f2c1f2a1f281f261f241f4e5e4e75')
    data = c.finish()
    validate_instruction_subset(data)
    if len(data) > 512:
        raise ValueError('program overlaps its shadow word')
    return {'workspace': workspace, 'shadow_target': shadow,
            'production_target': PRODUCTION_WORD, 'receipt': receipt, 'code': data,
            'modes': {'0': 'owned shadow function', '1': 'temporary production word'},
            'restores_before_return': True}


def rom_copy_plan(image, destination, data, base=0xa0001000):
    """Copy only to owned workspace; verify all constructed bytes before use.

    Source matches are limited to the immutable code/constant image region.
    The caller must pin the image, the copy routine and the allocation receipt.
    """
    if not isinstance(data, bytes) or not data or len(data) > ALLOCATION_BYTES:
        raise ValueError('require a bounded program byte string')
    haystack = image[:0xa0380000 - base]
    plan = []
    offset = 0
    while offset < len(data):
        for length in range(min(64, len(data) - offset), 0, -1):
            found = haystack.find(data[offset:offset + length])
            if found >= 0:
                plan.append((base + found, destination + offset, length))
                offset += length
                break
        else:
            raise ValueError('cannot construct program from immutable image slices')
    return plan
