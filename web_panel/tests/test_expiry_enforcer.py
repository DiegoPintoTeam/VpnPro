import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch


WEB_PANEL_DIR = __file__.rsplit('/tests/', 1)[0]
if WEB_PANEL_DIR not in sys.path:
    sys.path.insert(0, WEB_PANEL_DIR)

from services.ssh_service import SSHService


class ExpiryEnforcerTestCase(unittest.TestCase):
    def test_installs_a_minutely_systemd_enforcer(self):
        server = SimpleNamespace(ip='127.0.0.1', port=22, ssh_user='root', get_ssh_password=lambda: 'rootpass')
        service = SSHService(server)

        with patch.object(service, '_sftp_write') as write, patch.object(service, '_run', side_effect=[
            (False, '', ''),
            (True, '', ''),
        ]) as run:
            ok, message = service._ensure_expiry_enforcer()

        self.assertTrue(ok)
        self.assertEqual(message, '')
        self.assertIn('OnUnitActiveSec=1min', write.call_args_list[2].args[1])
        self.assertIn('usermod -L', write.call_args_list[0].args[1])
        self.assertIn('vpnpro-expiry-enforcer.timer', run.call_args.args[0])

    def test_renewal_only_unlocks_an_expiry_marker(self):
        server = SimpleNamespace(ip='127.0.0.1', port=22, ssh_user='root', get_ssh_password=lambda: 'rootpass')
        service = SSHService(server)

        with patch.object(service, '_connect_if_needed', return_value=(True, 'ok', False)), patch.object(
            service, '_run', return_value=(True, '', '')
        ) as run:
            ok, message = service.unblock_if_expiry_locked('DIEGO-PINTO')

        self.assertTrue(ok)
        self.assertEqual(message, '')
        command = run.call_args.args[0]
        self.assertIn('expiry-locks/DIEGO-PINTO', command)
        self.assertIn('usermod -U DIEGO-PINTO', command)


if __name__ == '__main__':
    unittest.main()