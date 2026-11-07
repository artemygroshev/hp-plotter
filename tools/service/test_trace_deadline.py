"""Ensure time-bound diagnostics refuse work before touching any device."""
from pathlib import Path
import datetime
import types
import unittest
from unittest.mock import patch

module=types.ModuleType('trace_under_test')
path=Path(__file__).parent/'trace_sequential_echo.py'
exec(compile(path.read_text(),str(path),'exec'),module.__dict__)

class PreflightReached(Exception):pass

class DeadlineChecks(unittest.TestCase):
    def context(self, second):
        class Clock:
            fromisoformat = staticmethod(datetime.datetime.fromisoformat)
            def __new__(cls,*args,**kwargs):return datetime.datetime(*args,**kwargs)
            @staticmethod
            def now(tz):return datetime.datetime(2026,11,7,18,second//60,second%60,tzinfo=tz)
        return patch.object(module,'datetime',types.SimpleNamespace(datetime=Clock,timezone=datetime.timezone))
    def test_cutoff_prevents_even_preflight(self):
        def snapshot(**kwargs):raise AssertionError('must not touch hardware after cutoff')
        for kind in ('echo','persistent','long_drain'):
            with self.subTest(kind=kind),self.context(39*60),self.assertRaisesRegex(RuntimeError,'deadline'):
                module.run({'snapshot':snapshot},{},None,kind=kind,deadline_utc='2026-11-07T18:39:00+00:00')
    def test_before_cutoff_reaches_readonly_preflight(self):
        def snapshot(**kwargs):raise PreflightReached()
        with self.context(38*60+59),self.assertRaises(PreflightReached):
            module.run({'snapshot':snapshot},{},None,kind='long_drain',deadline_utc='2026-11-07T18:39:00+00:00')

if __name__=='__main__':unittest.main()
