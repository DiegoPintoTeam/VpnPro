import os
import sys
import unittest
from unittest.mock import patch

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_PANEL_DIR = os.path.dirname(TESTS_DIR)
if WEB_PANEL_DIR not in sys.path:
    sys.path.insert(0, WEB_PANEL_DIR)

from app import create_app
from models import db, Reseller, Server, VpnUser
from routes.shared_utils import VPN_USERNAME_PATTERN, normalize_vpn_username


class _FakeCreateSSHService:
    def __init__(self, server):
        self.server = server

    def create_user(self, username: str, password: str, days: int, limit: int):
        return True, f"Usuario '{username}' creado."

    def schedule_demo_lock(self, username: str, hours: int):
        return True, ''


class UsernameNormalizationTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config.update(
            TESTING=True,
            WTF_CSRF_ENABLED=False,
            AUTO_SYNC_ENABLED=False,
            SQLALCHEMY_DATABASE_URI='sqlite:///:memory:',
        )

        with self.app.app_context():
            db.drop_all()
            db.create_all()

            self.server = Server(
                name='SrvFormat',
                ip='127.0.0.1',
                port=22,
                ssh_user='root',
                description='server format test',
            )
            self.server.ssh_password = 'rootpass'
            db.session.add(self.server)
            db.session.flush()

            self.reseller = Reseller(
                username='reseller_format',
                email='reseller@format.test',
                server_id=self.server.id,
                max_connections=5,
                panel_credits=30,
                is_active=True,
            )
            self.reseller.set_password('resellerpass')
            db.session.add(self.reseller)
            db.session.commit()

            self.server_id = int(self.server.id)

        self.client = self.app.test_client()

    def test_normalize_helper_accepts_mobile_dash_and_lowercase(self):
        raw_username = 'diego \u2013 pinto'
        normalized = normalize_vpn_username(raw_username)

        self.assertEqual(normalized, 'DIEGO-PINTO')
        self.assertIsNotNone(VPN_USERNAME_PATTERN.fullmatch(normalized))

    def test_normalize_helper_converts_accents_and_enye_to_ascii(self):
        raw_username = 'jos\u00e9-pi\u00f1to'
        normalized = normalize_vpn_username(raw_username)

        self.assertEqual(normalized, 'JOSE-PINTO')
        self.assertIsNotNone(VPN_USERNAME_PATTERN.fullmatch(normalized))

    def test_admin_create_user_accepts_lowercase_input(self):
        login_response = self.client.post(
            '/login',
            data={'username': 'VPNPro', 'password': '123456'},
            follow_redirects=False,
        )
        self.assertEqual(login_response.status_code, 302)

        with patch('routes.admin.SSHService', _FakeCreateSSHService):
            response = self.client.post(
                '/admin/users/create',
                data={
                    'username': 'diego \u2013 pinto',
                    'password': 'clave1234',
                    'package': '1m',
                    'limit': '1',
                    'server_id': str(self.server_id),
                    'create_as_admin': '1',
                },
                headers={'X-Requested-With': 'XMLHttpRequest'},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.get_json() or {}
        self.assertTrue(payload.get('ok'))
        self.assertEqual((payload.get('user') or {}).get('username'), 'DIEGO-PINTO')

        with self.app.app_context():
            created = VpnUser.query.filter_by(username='DIEGO-PINTO').first()
            self.assertIsNotNone(created)

    def test_reseller_create_user_accepts_lowercase_input(self):
        login_response = self.client.post(
            '/login',
            data={'username': 'reseller_format', 'password': 'resellerpass'},
            follow_redirects=False,
        )
        self.assertEqual(login_response.status_code, 302)

        with patch('routes.reseller.SSHService', _FakeCreateSSHService):
            response = self.client.post(
                '/reseller/users/create',
                data={
                    'username': 'diego \u2013 pinto',
                    'password': 'clave1234',
                    'package': '1m',
                    'limit': '1',
                },
                headers={'X-Requested-With': 'XMLHttpRequest'},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.get_json() or {}
        self.assertTrue(payload.get('ok'))
        self.assertEqual((payload.get('user') or {}).get('username'), 'DIEGO-PINTO')


if __name__ == '__main__':
    unittest.main()
