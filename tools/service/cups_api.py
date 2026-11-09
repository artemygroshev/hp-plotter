"""Bounded CUPS client for the LAN dashboard; never opens the USB device.

ipptool's plist output keeps job titles separate from protocol attributes.
Only this queue, three read operations and explicit per-job writes are exposed.
"""
import datetime as dt
import os
from pathlib import Path
import plistlib
import re
import subprocess
import tempfile
import threading
import time
from xml.parsers.expat import ExpatError

MAX_UPLOAD = 25 * 1024 * 1024
USER = 'hp-plotter'
FORMATS = {'application/pdf': (b'%PDF-', '.pdf'),
           'image/png': (b'\x89PNG\r\n\x1a\n', '.png'),
           'image/jpeg': (b'\xff\xd8\xff', '.jpg')}


class CupsError(Exception):
    def __init__(self, message, status=503):
        super().__init__(message)
        self.status = status


def clean(value, limit=500):
    return ''.join(c if ord(c) >= 32 else ' ' for c in str(value))[:limit]


class CupsClient:
    def __init__(self, queue='HP-DesignJet-500'):
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,126}', queue):
            raise ValueError('invalid CUPS queue')
        self.queue = queue
        self.uri = 'ipp://localhost:631/printers/' + queue
        self.lock = threading.Lock()
        self.cached = None
        self.cached_at = 0

    def run(self, args, text=None, timeout=8, write=False):
        try:
            p = subprocess.run(args, input=text, capture_output=True, text=True,
                               timeout=timeout, env={**os.environ, 'LC_ALL': 'C'})
        except (OSError, subprocess.TimeoutExpired) as exc:
            message = ('Ответ о задании не получен. Проверьте очередь перед повторной отправкой.'
                       if write else 'Очередь недоступна. Проверьте связь с CUPS и обновите панель.')
            raise CupsError(message) from exc
        if p.returncode or len(p.stdout.encode()) > 2 * 1024 * 1024:
            raise CupsError('CUPS не подтвердил действие. Проверьте очередь перед повтором.'
                            if write else 'Не удалось прочитать очередь CUPS. Обновите панель.')
        return p.stdout

    def block(self, operation, attributes, extra=''):
        return ('{\nOPERATION ' + operation + '\nGROUP operation-attributes-tag\n'
                'ATTR charset attributes-charset utf-8\n'
                'ATTR naturalLanguage attributes-natural-language en\n'
                'ATTR uri printer-uri ' + self.uri + '\n'
                'ATTR name requesting-user-name ' + USER + '\n' + extra +
                'ATTR keyword requested-attributes ' + ','.join(attributes) + '\n'
                'STATUS successful-ok\n}\n')

    def query(self, blocks):
        raw = self.run(['ipptool', '-X', '-T', '3', self.uri, '/dev/stdin'], ''.join(blocks), timeout=12)
        try:
            # CUPS 2.4 appends its human-readable summary after a multi-test plist.
            xml, end, tail = raw.partition('</plist>')
            expected = r'\s*Summary: '+str(len(blocks))+r' tests, '+str(len(blocks))+r' passed, 0 failed, 0 skipped\s+Score: 100%\s*'
            if not end or (tail.strip() and not re.fullmatch(expected, tail)):
                raise ValueError('unexpected text outside plist')
            data = plistlib.loads((xml+end).encode())
            tests = data['Tests']
            if data.get('Successful') is not True or len(tests) != len(blocks):
                raise ValueError('unsuccessful IPP result')
            if any(t.get('Successful') is not True or not isinstance(t.get('ResponseAttributes'), list) for t in tests):
                raise ValueError('incomplete IPP response')
            return [t['ResponseAttributes'] for t in tests]
        except (ValueError, KeyError, TypeError, ExpatError, plistlib.InvalidFileException) as exc:
            raise CupsError('CUPS вернул неполный ответ. Состояние очереди не подтверждено.') from exc

    def job(self, value):
        state = value.get('job-state')
        ident = value.get('job-id')
        if type(ident) is not int or ident <= 0 or type(state) is not int:
            raise CupsError('CUPS вернул неполное описание задания.')
        return {'id': ident, 'state': state, 'name': clean(value.get('job-name', 'Без названия')),
                'owner': clean(value.get('job-originating-user-name', '')),
                'size_kb': value.get('job-k-octets'),
                'pages_done': value.get('job-impressions-completed'),
                'created': value.get('time-at-creation'),
                'reasons': value.get('job-state-reasons', []),
                'can_control': value.get('job-originating-user-name') == USER and state in (3, 4, 5, 6)}

    def status(self, force=False):
        with self.lock:
            if not force and self.cached is not None and time.monotonic() - self.cached_at < 3:
                return self.cached
            attrs = ['job-id', 'job-state', 'job-name', 'job-originating-user-name',
                     'job-k-octets', 'job-impressions-completed', 'time-at-creation', 'job-state-reasons']
            replies = self.query([
                self.block('Get-Printer-Attributes', ['printer-state', 'printer-is-accepting-jobs',
                    'printer-state-message', 'printer-state-reasons', 'queued-job-count']),
                self.block('Get-Jobs', attrs, 'ATTR keyword which-jobs not-completed\nATTR integer limit 100\n'),
                self.block('Get-Jobs', attrs, 'ATTR keyword which-jobs completed\nATTR integer limit 10\n'),
            ])
            printer = next((v for v in replies[0] if 'printer-state' in v), None)
            if printer is None or type(printer.get('printer-state')) is not int:
                raise CupsError('Состояние CUPS не подтверждено.')
            active = [self.job(v) for v in replies[1] if 'job-id' in v]
            recent = [self.job(v) for v in replies[2] if 'job-id' in v]
            result = {'queue': self.queue, 'observed_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
                'source': 'CUPS', 'printer': {'state': printer['printer-state'],
                    'accepting': printer.get('printer-is-accepting-jobs'),
                    'message': clean(printer.get('printer-state-message', '')),
                    'reasons': printer.get('printer-state-reasons', [])},
                'active': active, 'recent': recent, 'active_truncated': len(active) >= 100,
                'roll_width_mm': 610, 'max_upload_bytes': MAX_UPLOAD}
            self.cached, self.cached_at = result, time.monotonic()
            return result

    def submit(self, data, mime, name, options):
        if mime not in FORMATS or not data or len(data) > MAX_UPLOAD:
            raise CupsError('Выберите PDF, PNG или JPEG размером до 25 МиБ.', 400)
        signature, suffix = FORMATS[mime]
        if not data.startswith(signature):
            raise CupsError('Содержимое файла не соответствует выбранному формату.', 400)
        if (not isinstance(name, str) or not name or len(name) > 180
                or any(c in '/\\' or ord(c)<32 for c in name)):
            raise CupsError('Укажите имя файла длиной до 180 символов без разделителей пути.', 400)
        if not isinstance(options, dict) or set(options) != {'length_mm', 'quality', 'hold'}:
            raise CupsError('Параметры печати не распознаны.', 400)
        length, quality, hold = options['length_mm'], options['quality'], options['hold']
        if (type(length) not in (int, float) or not 80 <= length <= 2000
                or quality not in ('draft', 'normal', 'presentation') or type(hold) is not bool):
            raise CupsError('Длина листа должна быть от 80 до 2000 мм. Проверьте качество и режим задания.', 400)
        args = ['lp', '-h', 'localhost:631', '-U', USER, '-d', self.queue, '-n', '1', '-t', name,
                '-o', 'PageSize=Custom.610x' + format(length, '.2f') + 'mm',
                '-o', 'InputSlot=RollPaperCut', '-o', 'Quality=' + quality,
                '-o', 'print-scaling=fit', '-o', 'page-ranges=1']
        if hold:
            args += ['-H', 'hold']
        path = None
        try:
            with tempfile.NamedTemporaryFile(prefix='hp-plotter-', suffix=suffix, delete=False) as f:
                path = Path(f.name)
                f.write(data)
            out = self.run(args + ['--', str(path)], timeout=18, write=True)
            match = re.search(r'^request id is ' + re.escape(self.queue) + r'-(\d+)\b', out)
            if not match:
                raise CupsError('Номер задания не получен. Проверьте очередь перед повторной отправкой.')
            self.cached = None
            return {'job_id': int(match.group(1)), 'held': hold, 'queue': self.queue}
        except OSError as exc:
            raise CupsError('Не удалось подготовить временный файл. Задание не подтверждено; проверьте очередь.') from exc
        finally:
            if path is not None:
                path.unlink(missing_ok=True)

    def action(self, ident, action):
        if type(ident) is not int or ident <= 0 or action not in ('cancel', 'release', 'hold'):
            raise CupsError('Задание не распознано.', 400)
        state = self.status(force=True)
        job = next((v for v in state['active'] if v['id'] == ident), None)
        if job is None:
            raise CupsError('Задание уже завершено или отсутствует в этой очереди.', 409)
        if not job['can_control']:
            raise CupsError('Это задание отправлено другим пользователем. Управление доступно в CUPS.', 403)
        if action == 'release' and job['state'] != 4:
            raise CupsError('Задание уже не находится на паузе. Обновите очередь.', 409)
        if action == 'hold' and job['state'] != 3:
            raise CupsError('Задание уже вышло из ожидания. Обновите очередь.', 409)
        request = self.queue + '-' + str(ident)
        args = (['cancel', '-h', 'localhost:631', '-U', USER, request] if action == 'cancel'
                else ['lp', '-h', 'localhost:631', '-U', USER, '-i', request, '-H',
                      'resume' if action == 'release' else 'hold'])
        self.run(args, write=True)
        self.cached = None
        return {'job_id': ident, 'action': action}
