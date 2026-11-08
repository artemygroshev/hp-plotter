"""External official image verification; firmware is never shipped in this repo."""
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'service'))
from reset_info import CODE_PROOFS,NO_INFO,RAIER


class ResetImageEvidence(unittest.TestCase):
    def test_complete_getter_and_wrapper_match_the_official_A04_image(self):
        folder=os.environ.get('HP_PLOTTER_FIXTURES')
        path=Path(folder)/'engine-A0402-main.bin' if folder else None
        if path is None or not path.is_file():self.skipTest('external official A.04.02 main image not supplied')
        data=path.read_bytes();base=0xa0001000
        self.assertEqual(hashlib.sha256(data).hexdigest(),'c882e68d2eb2462745f1ec984ce8f5ed745d2900587dce6b36acee5b89a1f4eb')
        for address,length,digest in CODE_PROOFS:
            raw=data[address-base:address-base+length]
            self.assertEqual(hashlib.sha256(raw).hexdigest(),digest)
            self.assertEqual(raw[-2:],b'\x4e\x75')  # complete RTS, not a cut prefix
        for address,value in ((0xa010cd98,b'Calling code: 0x%x\n'),
            (0xa010cdac,b'Kernel state: 0x%x\n'),(0xa010cdc0,b'Called from ISR\n'),
            (0xa010cdd4,b'Invalid TID\n'),(0xa010cde4,b'TID: 0x%x  PRIO: 0x%x\n'),
            (0xa010cdfc,b'Name: %c%c%c%c\n'),(0xa010ce0c,NO_INFO),(0xa010ce28,RAIER)):
            self.assertEqual(data[address-base:address-base+len(value)+1],value+b'\0')
        catalog=json.loads((Path(__file__).resolve().parents[2]/'docs/a04-capabilities.json').read_text())
        rows=catalog['commands_matching_this_registration_pattern']
        row=next(row for row in rows if row['name']=='sysShowResetInfo')
        self.assertEqual(row['handler'],'0xa026cf5c')


if __name__=='__main__':unittest.main()
