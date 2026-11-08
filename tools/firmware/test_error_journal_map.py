"""Check every fixed journal-map byte against an external official image."""
import hashlib
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'service'))
import error_journal as journal
import head_journal as heads


class JournalImageEvidence(unittest.TestCase):
    def image(self):
        folder=os.environ.get('HP_PLOTTER_FIXTURES')
        image=Path(folder)/'engine-A0402-main.bin' if folder else None
        if image is None or not image.is_file():self.skipTest('external official A.04.02 main image not supplied')
        return image.read_bytes()

    def test_official_image_layout_and_all_code_proofs(self):
        folder=os.environ.get('HP_PLOTTER_FIXTURES')
        image=Path(folder)/'engine-A0402-main.bin' if folder else None
        if image is None or not image.is_file():
            self.skipTest('external official A.04.02 main image not supplied')
        data=image.read_bytes();base=0xa0001000
        self.assertEqual(hashlib.sha256(data).hexdigest(),
            'c882e68d2eb2462745f1ec984ce8f5ed745d2900587dce6b36acee5b89a1f4eb')
        for address,length,digest in journal.CODE_PROOFS:
            self.assertEqual(hashlib.sha256(data[address-base:address-base+length]).hexdigest(),digest)
        self.assertEqual(data[journal.DESCRIPTORS_ADDRESS-base:journal.DESCRIPTORS_ADDRESS-base+110],journal.DESCRIPTORS)
        self.assertEqual(journal.parse_config(data[journal.CONFIG_ADDRESS-base:journal.CONFIG_ADDRESS-base+12])['table_version'],6)
        self.assertEqual(data[0xa0296480-base:0xa0296480-base+11],b' %02d:%02d\0')

    def test_head_layout_and_color_tables_match_official_code(self):
        data=self.image();base=0xa0001000
        for address,length,digest in heads.CODE_PROOFS:
            self.assertEqual(hashlib.sha256(data[address-base:address-base+length]).hexdigest(),digest)
        for address,expected in ((heads.MAP_ADDRESS,heads.MAP),(heads.DESCRIPTORS_ADDRESS,heads.DESCRIPTORS),
                                 (heads.COLOR_MAP_ADDRESS,heads.COLOR_MAP)):
            self.assertEqual(data[address-base:address-base+len(expected)],expected)
        self.assertEqual(list(zip(heads.MAP[:14:2],heads.MAP[1:14:2])),[(0,4),(8,2),(10,2),(12,2),(4,4),(14,1),(14,1)])

    def test_python_head_code_matches_original_machine_code_priority(self):
        data=self.image();base=0xa0001000
        import random,struct
        def native(mask):
            # Tiny independent interpreter for the exact leaf's instructions.
            # Operands and branches come from the official bytes, not our table.
            start=0xa00ef4ac;pc=start+8;registers=[0,mask]+[0]*6;zero=False;negative=False
            for _ in range(200):
                op=struct.unpack_from('>H',data,pc-base)[0];pc+=2
                if op&0xf100==0x7000:
                    r=(op>>9)&7;v=op&255;registers[r]=(v-256 if v&128 else v)&0xffffffff
                    zero=registers[r]==0;negative=bool(registers[r]&0x80000000)
                elif op==0xc081:
                    registers[0]&=registers[1];zero=registers[0]==0;negative=bool(registers[0]&0x80000000)
                elif op==0x0801:
                    bit=struct.unpack_from('>H',data,pc-base)[0];pc+=2
                    zero=not bool(registers[1]&(1<<(bit%32)))
                elif op in (0x4a41,0x4a01):
                    width=16 if op==0x4a41 else 8;v=registers[1]&((1<<width)-1)
                    zero=v==0;negative=bool(v&(1<<(width-1)))
                elif op&0xff00 in (0x6000,0x6700,0x6a00):
                    branch_from=pc;offset=op&255
                    if offset==0:offset=struct.unpack_from('>h',data,pc-base)[0];pc+=2
                    elif offset&128:offset-=256
                    if op&0xff00==0x6000 or (op&0xff00==0x6700 and zero) or (op&0xff00==0x6a00 and not negative):pc=branch_from+offset
                elif op==0x4e5e:return registers[0]
                else:self.fail('unsupported original opcode '+hex(op))
            self.fail('original leaf did not return')
        masks=[0]+[1<<i for i in range(32)]+[(1<<i)|(1<<j) for i in range(32) for j in range(i,32)]
        rng=random.Random(500);masks.extend(rng.getrandbits(32) for _ in range(4096))
        for mask in masks:
            for color,prefix in enumerate((0,2,1,3)):
                expected=(f'{100*(prefix+(10 if mask&8 else 0))+native(mask):04d}' if mask&heads.ERROR_MASK else None)
                self.assertEqual(heads.native_head_code(color,mask),expected,(color,hex(mask)))


if __name__=='__main__':unittest.main()
