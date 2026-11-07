"""Load installation-specific pins from an untracked private JSON file."""
import json
import os
from pathlib import Path
import re

PROJECT = Path(__file__).resolve().parents[2]
DEFAULTS = {
    'ssh_target': 'btt-plotter',
    'known_hosts': '~/.ssh/known_hosts',
    'machine_id': '00000000000000000000000000000000',
    'printer_serial': 'UNCONFIGURED',
    'adapter_descriptor_sha256': 'd5e1ee6bc5732b93ec44b7830dd57ff82b7a044cd6064809e1d642c6aae3cf1e',
    'queue': 'HP-DesignJet-500',
    'password_file': None,
}


def configuration(required=True):
    path = Path(os.environ.get('HP_PLOTTER_CONFIG', PROJECT/'config.local.json')).expanduser()
    config = DEFAULTS.copy()
    if path.exists():
        data = json.loads(path.read_text())
        if not isinstance(data, dict) or set(data)-set(DEFAULTS):
            raise ValueError('unknown configuration fields')
        config.update(data)
    if required:
        if not path.is_file():
            raise RuntimeError('configure an untracked config.local.json or HP_PLOTTER_CONFIG first')
        if (not re.fullmatch(r'[0-9a-f]{32}',config['machine_id'])
                or config['machine_id'] == DEFAULTS['machine_id']):
            raise ValueError('pin the target machine-id before connecting')
        if (not re.fullmatch(r'[A-Za-z0-9_-]{1,40}',config['printer_serial'])
                or config['printer_serial'] == 'UNCONFIGURED'):
            raise ValueError('pin the actual printer serial before connecting')
        if not re.fullmatch(r'[0-9a-f]{64}',config['adapter_descriptor_sha256']):
            raise ValueError('invalid adapter descriptor pin')
        if not re.fullmatch(r'[A-Za-z0-9_.@:-]+',config['ssh_target']) or config['ssh_target'].startswith('-'):
            raise ValueError('SSH target must be a host alias or user@host')
        if not re.fullmatch(r'[A-Za-z0-9_-]+',config['queue']):
            raise ValueError('invalid CUPS queue name')
        config['known_hosts'] = str(Path(config['known_hosts']).expanduser().resolve())
        if not Path(config['known_hosts']).is_file():
            raise ValueError('a verified known_hosts file is required')
    return config


def private_password(config):
    if not config['password_file']:
        return None
    path = Path(config['password_file']).expanduser()
    stat = path.stat()
    if stat.st_uid != os.getuid() or stat.st_mode & 0o077 or stat.st_size > 1024:
        raise ValueError('password file must be owned by the caller and mode 0600')
    value = path.read_text().rstrip('\n')
    if not value or '\n' in value or '\r' in value:
        raise ValueError('password file must contain one nonempty line')
    return value
