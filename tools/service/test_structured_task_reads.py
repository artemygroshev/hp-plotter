import unittest
from structured_task_reads import TaskReadSession


class StructuredTaskChecks(unittest.TestCase):
    def session(self):
        session = object.__new__(TaskReadSession)
        session.workspace = 0xa1800000
        session.plans = {}
        session.queries = []
        session.task_ids = (0xa1802000, 0xa1803000, 0xa1804000, 0xa1805000)
        session.name_addresses = set()
        return session

    def test_fixed_group_fits_and_never_addresses_another_task(self):
        session = self.session()
        session.schedule('tasks_info_0')
        self.assertEqual(len(session.command_payload('tasks_info_0', '111aaa')), 513)
        for stage in ('tasks_info_4', 'tasks_info_1', 'task_delete'):
            with self.subTest(stage=stage), self.assertRaises(ValueError):
                session.schedule(stage)

    def test_other_memory_and_operation_replay_are_rejected(self):
        session = self.session()
        with self.assertRaises(ValueError):
            session.command_payload('runtime_mem', '111aaa', (0xa1801200, 128))
        session.schedule('tasks_ids_before')
        session.queries.append({'kind': 'tasks_ids_before'})
        with self.assertRaises(RuntimeError):
            session.command_payload('tasks_ids_before', '222bbb')

    def test_free_revokes_the_buffer_and_name_window(self):
        session = self.session()
        session.name_addresses.add(0xa1806000)
        session.schedule('tasks_free')
        session.validate_reply('tasks_free', '111aaa', b'B111aaa\n0\nE111aaa\n', None, {})
        self.assertIsNone(session.workspace)
        self.assertFalse(session.name_addresses)
        with self.assertRaises(ValueError):
            session.schedule('tasks_ids_after')


if __name__ == '__main__':
    unittest.main()
