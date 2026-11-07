"""Private atomic JSON checkpoints for local captures."""
import os,json,tempfile
from pathlib import Path

def atomic_json(path,value):
    if path.exists() and path.stat().st_uid != os.getuid():
        raise RuntimeError('checkpoint belongs to another user')
    with tempfile.NamedTemporaryFile(mode='w',dir=path.parent,prefix='.lcd-checkpoint-',delete=False) as out:
        temp=Path(out.name)
        os.chmod(temp,0o600)
        json.dump(value,out,indent=2)
        out.write('\n')
    os.replace(temp,path)
