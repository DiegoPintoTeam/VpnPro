import unittest
from types import SimpleNamespace
from unittest.mock import patch

from services.ssh_service import SSHService


class SSHServiceIdempotencyTestCase(unittest.TestCase):
    def _build_service(self) -> SSHService:
        fake_server = SimpleNamespace(
            ip='127.0.0.1',
            port=22,
            ssh_user='root',
            get_ssh_password=lambda: 'rootpass',
        )
        return SSHService(fake_server)

    def test_delete_user_is_idempotent_when_missing_user(self):
        svc = self._build_service()

        with patch.object(svc, '_connect_if_needed', return_value=(True, 'ok', False)), \
             patch.object(svc, '_run', side_effect=[
                 (True, '', ''),
                 (False, '', 'userdel: user TEST-USER does not exist'),
             ]), \
             patch.object(svc, '_sftp_read', return_value=''), \
             patch.object(svc, '_sftp_write', return_value=None), \
             patch.object(svc, '_sftp_remove', return_value=None):
            ok, msg = svc.delete_user('TEST-USER')

        self.assertTrue(ok)
        self.assertIn('eliminado', msg.lower())

    def test_block_user_is_idempotent_when_missing_user(self):
        svc = self._build_service()

        with patch.object(svc, '_connect_if_needed', return_value=(True, 'ok', False)), \
             patch.object(svc, '_run', side_effect=[
                 (True, '', ''),
                 (False, '', 'usermod: user TEST-USER does not exist'),
             ]):
            ok, msg = svc.block_user('TEST-USER')

        self.assertTrue(ok)
        self.assertIn('idempotente', msg.lower())

    def test_delete_user_reports_stdout_detail_on_failure(self):
        svc = self._build_service()

        with patch.object(svc, '_connect_if_needed', return_value=(True, 'ok', False)), \
             patch.object(svc, '_run', side_effect=[
                 (True, '', ''),
                 (False, 'userdel: Permission denied', ''),
             ]):
            ok, msg = svc.delete_user('TEST-USER')

        self.assertFalse(ok)
        self.assertIn('permission denied', msg.lower())

    def test_block_user_reports_stdout_detail_on_failure(self):
        svc = self._build_service()

        with patch.object(svc, '_connect_if_needed', return_value=(True, 'ok', False)), \
             patch.object(svc, '_run', side_effect=[
                 (True, '', ''),
                 (False, 'usermod: Permission denied', ''),
             ]):
            ok, msg = svc.block_user('TEST-USER')

        self.assertFalse(ok)
        self.assertIn('permission denied', msg.lower())

    def test_delete_user_reports_disk_full_and_passwd_lock_actionable_message(self):
        svc = self._build_service()

        with patch.object(svc, '_connect_if_needed', return_value=(True, 'ok', False)), \
             patch.object(svc, '_run', side_effect=[
                 (True, '', ''),
                 (False, 'userdel: /etc/passwd.123 file write error: No space left on device\nuserdel: cannot lock /etc/passwd; try again later.', ''),
                 (True, 'overlay 20G 20G 0 100% /', ''),
                 (True, 'overlay 1000000 1000000 0 100% /', ''),
             ]):
            ok, msg = svc.delete_user('TEST-USER')

        self.assertFalse(ok)
        self.assertIn('falta de espacio', msg.lower())
        self.assertIn('disco:', msg.lower())
        self.assertIn('inodos:', msg.lower())

    def test_create_user_reports_disk_full_when_sftp_write_fails(self):
        svc = self._build_service()

        with patch.object(svc, '_connect_if_needed', return_value=(True, 'ok', False)), \
             patch.object(svc, '_run', side_effect=[
                 (True, 'NEW', ''),
                 (True, '', ''),
                 (True, '', ''),
                 (True, '', ''),
             ]), \
             patch.object(svc, '_sftp_write', side_effect=OSError('No space left on device')):
            ok, msg = svc.create_user('TEST-USER', 'pass1234', 1, 1)

        self.assertFalse(ok)
        self.assertIn('falta de espacio', msg.lower())

    def test_change_password_reports_disk_full_when_sftp_write_fails(self):
        svc = self._build_service()

        with patch.object(svc, 'connect', return_value=(True, 'ok')), \
             patch.object(svc, '_set_password_stdin', return_value=(True, '')),
             patch.object(svc, '_sftp_write', side_effect=OSError('No space left on device')):
            ok, msg = svc.change_password('TEST-USER', 'newpass')

        self.assertFalse(ok)
        self.assertIn('falta de espacio', msg.lower())

    def test_run_disk_housekeeping_skips_below_trigger(self):
        svc = self._build_service()

        with patch.object(svc, '_connect_if_needed', return_value=(True, 'ok', False)), \
             patch.object(svc, '_run', side_effect=[
                 (True, '/dev/sda1 100000 90000 10000 90% /', ''),
                 (True, '/dev/sda1 1000000 10000 990000 1% /', ''),
             ]):
            ok, report, err = svc.run_disk_housekeeping(trigger_percent=92)

        self.assertTrue(ok)
        self.assertEqual(err, '')
        self.assertFalse(report['ran'])

    def test_run_disk_housekeeping_runs_when_trigger_reached(self):
        svc = self._build_service()

        with patch.object(svc, '_connect_if_needed', return_value=(True, 'ok', False)), \
             patch.object(svc, '_run', side_effect=[
                 (True, '/dev/sda1 100000 98000 2000 98% /', ''),
                 (True, '/dev/sda1 1000000 10000 990000 1% /', ''),
                 (True, '', ''),
                 (True, '', ''),
                 (True, '', ''),
                 (True, '/dev/sda1 100000 93000 7000 93% /', ''),
                 (True, '/dev/sda1 1000000 11000 989000 2% /', ''),
             ]):
            ok, report, err = svc.run_disk_housekeeping(trigger_percent=92)

        self.assertTrue(ok)
        self.assertEqual(err, '')
        self.assertTrue(report['ran'])
        self.assertGreaterEqual(int(report.get('freed_percent_points', 0)), 5)

    def test_get_online_user_snapshot_returns_connected_seconds_from_sshd_process(self):
        svc = self._build_service()

        with patch.object(svc, 'connect', return_value=(True, 'ok')), \
             patch.object(svc, 'disconnect', return_value=None), \
             patch.object(svc, '_run', side_effect=[
                 (True, 'ESTAB 0 0 10.0.0.1:22 1.1.1.1:50000 users:(("sshd",pid=101,fd=4))\nESTAB 0 0 10.0.0.1:22 2.2.2.2:50001 users:(("sshd",pid=102,fd=4))', ''),
                 (True, '101 3661 sshd: TEST-USER@pts/0\n102 120 sshd: TEST-USER@pts/1', ''),
             ]):
            ok, sessions_by_user, devices_by_user, connected_seconds_by_user, err = svc.get_online_user_snapshot()

        self.assertTrue(ok)
        self.assertEqual(err, '')
        self.assertEqual(sessions_by_user, {'TEST-USER': 2})
        self.assertEqual(devices_by_user, {'TEST-USER': 2})
        self.assertEqual(connected_seconds_by_user, {'TEST-USER': 3661})

    def test_trim_user_sessions_keeps_newest_connection(self):
        svc = self._build_service()

        with patch.object(svc, '_connect_if_needed', return_value=(True, 'ok', False)), \
             patch.object(svc, '_run', side_effect=[
                 (True, '101 3661\n102 120', ''),
                 (True, '', ''),
             ]):
            ok, killed, msg = svc.trim_user_sessions('TEST-USER', keep_sessions=1)

        self.assertTrue(ok)
        self.assertEqual(killed, 1)
        self.assertIn('cerradas: 1', msg.lower())
        self.assertEqual(svc._run.call_args_list[1].args[0], 'kill -9 101 >/dev/null 2>&1 || true')


if __name__ == '__main__':
    unittest.main()