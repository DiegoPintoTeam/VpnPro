import io
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from unittest.mock import patch

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_PANEL_DIR = os.path.dirname(TESTS_DIR)
if WEB_PANEL_DIR not in sys.path:
    sys.path.insert(0, WEB_PANEL_DIR)

from app import create_app
from config import Config
from models import db, Reseller, Server, VpnUser
from routes.admin import (
    SYSTEM_ADMIN_RESELLER_NOTE,
    _background_transfer_server_users,
    _cached_dashboard_server_metrics_payload,
    _build_transfer_users_preview,
    _transfer_server_records_db_only,
)
from routes.shared_utils import (
    auto_block_users_exceeding_limit,
    cache_online_snapshot,
    cache_get,
    cache_set,
    compose_action_error,
    get_cached_online_snapshot,
    respond_user_action,
    serialize_user_for_ui,
)


class _FakeSSHService:
    blocked_usernames = []
    unblocked_usernames = []
    trimmed_usernames = []

    def __init__(self, server):
        self.server = server

    def block_user(self, username: str):
        _FakeSSHService.blocked_usernames.append(username)
        return True, f"Usuario '{username}' bloqueado."

    def unblock_user(self, username: str):
        _FakeSSHService.unblocked_usernames.append(username)
        return True, f"Usuario '{username}' desbloqueado."

    def trim_user_sessions(self, username: str, keep_sessions: int = 1):
        _FakeSSHService.trimmed_usernames.append((username, keep_sessions))
        return True, 1, 'Sesiones excedentes cerradas: 1'

    def inspect_user_state(self, username: str):
        return True, {
            'username': username,
            'checks': {
                'id': {'ok': True, 'stdout': f'uid=1000({username}) gid=1000({username})', 'stderr': ''},
            },
        }

    def get_root_storage_status(self):
        return True, {
            'blocks': '/dev/sda1 72000000 30000000 42000000 41% /',
            'inodes': '/dev/sda1 1000000 10000 990000 1% /',
            'blocks_used_percent': 41,
            'inodes_used_percent': 1,
        }, ''

    def run_disk_housekeeping(
        self,
        trigger_percent: int = 92,
        journal_max_mb: int = 200,
        tmp_max_age_days: int = 3,
        aggressive: bool = False,
    ):
        return True, {
            'ran': False,
            'before': {
                'blocks_used_percent': 41,
            },
            'after': {
                'blocks_used_percent': 41,
            },
            'freed_percent_points': 0,
        }, ''


class _FakeTransferSSHService(_FakeSSHService):
    created_usernames = []
    deleted_usernames = []

    def connect(self):
        return True, ''

    def disconnect(self):
        return True, ''

    def create_user(self, username: str, password: str, days: int, limit: int):
        self.created_usernames.append((self.server.id, username, days, limit))
        return True, f"Usuario '{username}' creado."

    def set_expiry_date(self, username: str, expiry_date):
        return True, f"Expiracion ajustada para '{username}'."

    def delete_user(self, username: str):
        self.deleted_usernames.append((self.server.id, username))
        return True, f"Usuario '{username}' eliminado."

    def schedule_demo_lock(self, username: str, hours: int):
        return True, ''


class BlockRoutesTestCase(unittest.TestCase):
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
                name='SrvTest',
                ip='127.0.0.1',
                port=22,
                ssh_user='root',
                description='server test',
            )
            self.server.ssh_password = 'rootpass'
            db.session.add(self.server)
            db.session.flush()

            self.server_target = Server(
                name='SrvTarget',
                ip='127.0.0.2',
                port=22,
                ssh_user='root',
                description='server target test',
            )
            self.server_target.ssh_password = 'rootpass2'
            db.session.add(self.server_target)
            db.session.flush()

            self.reseller = Reseller(
                username='reseller_test',
                email='reseller@test.local',
                server_id=self.server.id,
                max_connections=2,
                panel_credits=20,
                is_active=True,
            )
            self.reseller.set_password('resellerpass')
            db.session.add(self.reseller)
            db.session.flush()

            self.user = VpnUser(
                username='USUARIO-PRUEBA',
                password='clave123',
                connection_limit=1,
                expiry_date=datetime.utcnow() + timedelta(days=30),
                reseller_id=self.reseller.id,
                server_id=self.server.id,
                is_active=True,
                is_blocked=False,
            )
            db.session.add(self.user)
            db.session.commit()

            self.user_id = self.user.id
            self.username = self.user.username
            self.target_server_id = self.server_target.id

        self.client = self.app.test_client()

    def _reload_user(self):
        with self.app.app_context():
            return db.session.get(VpnUser, self.user_id)

    def test_admin_block_route_blocks_user(self):
        _FakeSSHService.blocked_usernames = []

        login_response = self.client.post(
            '/login',
            data={'username': 'VPNPro', 'password': '123456'},
            follow_redirects=False,
        )
        self.assertEqual(login_response.status_code, 302)

        with patch('routes.admin.SSHService', _FakeSSHService):
            response = self.client.post(f'/admin/users/{self.user_id}/block', follow_redirects=False)

        self.assertEqual(response.status_code, 302)

        updated = self._reload_user()
        self.assertIsNotNone(updated)
        self.assertTrue(updated.is_blocked)
        self.assertIn(self.username, _FakeSSHService.blocked_usernames)

    def test_admin_unblock_route_unblocks_and_trims(self):
        _FakeSSHService.unblocked_usernames = []
        _FakeSSHService.trimmed_usernames = []

        with self.app.app_context():
            user = db.session.get(VpnUser, self.user_id)
            user.is_blocked = True
            db.session.commit()

        login_response = self.client.post(
            '/login',
            data={'username': 'VPNPro', 'password': '123456'},
            follow_redirects=False,
        )
        self.assertEqual(login_response.status_code, 302)

        with patch('routes.admin.SSHService', _FakeSSHService):
            response = self.client.post(f'/admin/users/{self.user_id}/unblock', follow_redirects=False)

        self.assertEqual(response.status_code, 302)

        updated = self._reload_user()
        self.assertIsNotNone(updated)
        self.assertFalse(updated.is_blocked)
        self.assertIn(self.username, _FakeSSHService.unblocked_usernames)
        self.assertIn((self.username, 1), _FakeSSHService.trimmed_usernames)

    def test_reseller_block_route_blocks_user(self):
        _FakeSSHService.blocked_usernames = []

        login_response = self.client.post(
            '/login',
            data={'username': 'reseller_test', 'password': 'resellerpass'},
            follow_redirects=False,
        )
        self.assertEqual(login_response.status_code, 302)

        with patch('routes.reseller.SSHService', _FakeSSHService):
            response = self.client.post(f'/reseller/users/{self.user_id}/block', follow_redirects=False)

        self.assertEqual(response.status_code, 302)

        updated = self._reload_user()
        self.assertIsNotNone(updated)
        self.assertTrue(updated.is_blocked)
        self.assertIn(self.username, _FakeSSHService.blocked_usernames)

    def test_reseller_unblock_route_unblocks_limit_blocked_user(self):
        _FakeSSHService.unblocked_usernames = []
        _FakeSSHService.trimmed_usernames = []

        with self.app.app_context():
            user = db.session.get(VpnUser, self.user_id)
            user.is_blocked = True
            db.session.commit()

        login_response = self.client.post(
            '/login',
            data={'username': 'reseller_test', 'password': 'resellerpass'},
            follow_redirects=False,
        )
        self.assertEqual(login_response.status_code, 302)

        with patch('routes.reseller.SSHService', _FakeSSHService):
            response = self.client.post(f'/reseller/users/{self.user_id}/unblock', follow_redirects=False)

        self.assertEqual(response.status_code, 302)

        updated = self._reload_user()
        self.assertIsNotNone(updated)
        self.assertFalse(updated.is_blocked)
        self.assertIn(self.username, _FakeSSHService.unblocked_usernames)
        self.assertIn((self.username, 1), _FakeSSHService.trimmed_usernames)

    def test_edit_reseller_moves_owned_users_to_new_server(self):
        login_response = self.client.post(
            '/login',
            data={'username': 'VPNPro', 'password': '123456'},
            follow_redirects=False,
        )
        self.assertEqual(login_response.status_code, 302)

        response = self.client.post(
            f'/admin/resellers/{self.reseller.id}/edit',
            data={
                'email': 'reseller@test.local',
                'server_id': str(self.target_server_id),
                'max_connections': '2',
                'panel_credits': '20',
                'note': '',
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 302)

        with self.app.app_context():
            reseller = db.session.get(Reseller, self.reseller.id)
            user = db.session.get(VpnUser, self.user_id)

            self.assertIsNotNone(reseller)
            self.assertIsNotNone(user)
            self.assertEqual(reseller.server_id, self.target_server_id)
            self.assertEqual(user.server_id, self.target_server_id)

    def test_transfer_users_preview_estimates_resellers_to_move(self):
        with self.app.app_context():
            source = db.session.get(Server, self.server.id)
            target = db.session.get(Server, self.target_server_id)

            stats = _build_transfer_users_preview(source, target)

        self.assertEqual(stats.get('total_source'), 1)
        self.assertEqual(stats.get('resellers_to_move_estimate'), 1)

    def test_transfer_users_preview_counts_reseller_even_without_users(self):
        with self.app.app_context():
            empty_source = Server(
                name='SrvEmptySource',
                ip='127.0.0.10',
                port=22,
                ssh_user='root',
                description='empty source server',
            )
            empty_source.ssh_password = 'rootpass-empty'
            db.session.add(empty_source)
            db.session.flush()

            empty_reseller = Reseller(
                username='reseller_empty_preview',
                email='empty-preview@test.local',
                server_id=empty_source.id,
                max_connections=1,
                panel_credits=0,
                is_active=True,
            )
            empty_reseller.set_password('resellerpass')
            db.session.add(empty_reseller)
            db.session.commit()

            source = db.session.get(Server, empty_source.id)
            target = db.session.get(Server, self.target_server_id)
            stats = _build_transfer_users_preview(source, target)

        self.assertEqual(stats.get('total_source'), 0)
        self.assertEqual(stats.get('resellers_to_move_estimate'), 1)

    def test_background_transfer_moves_reseller_with_user(self):
        _FakeTransferSSHService.created_usernames = []
        _FakeTransferSSHService.deleted_usernames = []

        with patch('routes.admin.SSHService', _FakeTransferSSHService), patch(
            'routes.admin._update_delete_sync_status',
            lambda *args, **kwargs: None,
        ):
            _background_transfer_server_users(
                self.app,
                'sync-test',
                self.server.id,
                self.target_server_id,
                [self.user_id],
            )

        with self.app.app_context():
            reseller = db.session.get(Reseller, self.reseller.id)
            user = db.session.get(VpnUser, self.user_id)

            self.assertIsNotNone(reseller)
            self.assertIsNotNone(user)
            self.assertEqual(user.server_id, self.target_server_id)
            self.assertEqual(user.reseller_id, self.reseller.id)
            self.assertEqual(reseller.server_id, self.target_server_id)

    def test_background_transfer_moves_reseller_even_without_users(self):
        _FakeTransferSSHService.created_usernames = []
        _FakeTransferSSHService.deleted_usernames = []

        with self.app.app_context():
            empty_source = Server(
                name='SrvEmptyTransfer',
                ip='127.0.0.11',
                port=22,
                ssh_user='root',
                description='empty transfer source',
            )
            empty_source.ssh_password = 'rootpass-empty-transfer'
            db.session.add(empty_source)
            db.session.flush()

            empty_reseller = Reseller(
                username='reseller_empty_transfer',
                email='empty-transfer@test.local',
                server_id=empty_source.id,
                max_connections=1,
                panel_credits=0,
                is_active=True,
            )
            empty_reseller.set_password('resellerpass')
            db.session.add(empty_reseller)
            db.session.commit()

            empty_source_id = int(empty_source.id)
            empty_reseller_id = int(empty_reseller.id)

        with patch('routes.admin.SSHService', _FakeTransferSSHService), patch(
            'routes.admin._update_delete_sync_status',
            lambda *args, **kwargs: None,
        ):
            _background_transfer_server_users(
                self.app,
                'sync-empty-test',
                empty_source_id,
                self.target_server_id,
                [],
            )

        with self.app.app_context():
            reseller = db.session.get(Reseller, empty_reseller_id)
            self.assertIsNotNone(reseller)
            self.assertEqual(reseller.server_id, self.target_server_id)

    def test_transfer_users_route_enqueues_when_only_resellers_exist(self):
        with self.app.app_context():
            empty_source = Server(
                name='SrvOnlyResellers',
                ip='127.0.0.12',
                port=22,
                ssh_user='root',
                description='route-only-resellers source',
            )
            empty_source.ssh_password = 'rootpass-only-resellers'
            db.session.add(empty_source)
            db.session.flush()

            empty_reseller = Reseller(
                username='reseller_only_resellers',
                email='only-resellers@test.local',
                server_id=empty_source.id,
                max_connections=1,
                panel_credits=0,
                is_active=True,
            )
            empty_reseller.set_password('resellerpass')
            db.session.add(empty_reseller)
            db.session.commit()

            empty_source_id = int(empty_source.id)

        login_response = self.client.post(
            '/login',
            data={'username': 'VPNPro', 'password': '123456'},
            follow_redirects=False,
        )
        self.assertEqual(login_response.status_code, 302)

        with patch('routes.admin._start_transfer_users_background_sync', return_value='sync-route-test') as start_sync:
            response = self.client.post(
                f'/admin/servers/{empty_source_id}/transfer-users',
                data={'target_server_id': str(self.target_server_id)},
                follow_redirects=False,
            )

        self.assertEqual(response.status_code, 302)
        start_sync.assert_called_once()

        with self.client.session_transaction() as session:
            flashes = session.get('_flashes', [])
        joined = ' | '.join(msg for _cat, msg in flashes)
        self.assertIn('Transferencia encolada', joined)
        self.assertIn('usuarios=0, revendedores=1', joined)

    def test_reconcile_resellers_moves_to_majority_server(self):
        with self.app.app_context():
            # Crear mayoría de usuarios activos del reseller en servidor destino.
            user_majority_a = VpnUser(
                username='USUARIO-MAYORIA-A',
                password='clave123',
                connection_limit=1,
                expiry_date=datetime.utcnow() + timedelta(days=30),
                reseller_id=self.reseller.id,
                server_id=self.target_server_id,
                is_active=True,
                is_blocked=False,
            )
            user_majority_b = VpnUser(
                username='USUARIO-MAYORIA-B',
                password='clave123',
                connection_limit=1,
                expiry_date=datetime.utcnow() + timedelta(days=30),
                reseller_id=self.reseller.id,
                server_id=self.target_server_id,
                is_active=True,
                is_blocked=False,
            )
            db.session.add_all([user_majority_a, user_majority_b])
            db.session.commit()

        login_response = self.client.post(
            '/login',
            data={'username': 'VPNPro', 'password': '123456'},
            follow_redirects=False,
        )
        self.assertEqual(login_response.status_code, 302)

        response = self.client.post('/admin/servers/reconcile-resellers', follow_redirects=False)
        self.assertEqual(response.status_code, 302)

        with self.app.app_context():
            reseller = db.session.get(Reseller, self.reseller.id)
            user = db.session.get(VpnUser, self.user_id)
            self.assertIsNotNone(reseller)
            self.assertIsNotNone(user)
            self.assertEqual(reseller.server_id, self.target_server_id)
            self.assertEqual(user.server_id, self.target_server_id)

    def test_reconcile_resellers_noop_when_already_aligned(self):
        # El setUp crea reseller y usuario en self.server, ambos ya alineados entre sí.
        # No se requiere cambio de estado previo; reconciliar debe retornar 'Todo reconciliado'.
        login_response = self.client.post(
            '/login',
            data={'username': 'VPNPro', 'password': '123456'},
            follow_redirects=False,
        )
        self.assertEqual(login_response.status_code, 302)

        response = self.client.post('/admin/servers/reconcile-resellers', follow_redirects=False)
        self.assertEqual(response.status_code, 302)

        with self.client.session_transaction() as session:
            flashes = session.get('_flashes', [])
        joined = ' | '.join(msg for _cat, msg in flashes)
        self.assertIn('Todo reconciliado', joined)

    def test_online_snapshot_cache_normalizes_server_maps(self):
        with self.app.app_context():
            cache_online_snapshot(
                self.server.id,
                {' usuario-prueba ': 2},
                device_map={' usuario-prueba ': 1},
                connected_seconds_map={' usuario-prueba ': 3661},
            )
            snapshot = get_cached_online_snapshot(self.server.id)

        self.assertIsNotNone(snapshot)
        self.assertEqual(snapshot.get('online_map'), {'USUARIO-PRUEBA': 2})
        self.assertEqual(snapshot.get('device_map'), {'USUARIO-PRUEBA': 1})
        self.assertEqual(snapshot.get('connected_seconds_map'), {'USUARIO-PRUEBA': 3661})

    def test_dashboard_metrics_payload_uses_shared_cache(self):
        calls = {'count': 0}

        def _fake_cached_server_info(server, allow_refresh=True):
            calls['count'] += 1
            return True, {
                'cpu': '10%',
                'ram': '100 / 500 MB',
                'disk': '10G / 20G (50%)',
                'uptime': 'up 1 hour',
                'online': '1',
            }, ''

        with self.app.app_context():
            with patch('routes.admin._cached_server_info', side_effect=_fake_cached_server_info):
                first = _cached_dashboard_server_metrics_payload([self.server])
                second = _cached_dashboard_server_metrics_payload([self.server])

        self.assertEqual(calls['count'], 1)
        self.assertEqual(first, second)
        self.assertEqual(first[str(self.server.id)]['cpu'], '10%')

    def test_admin_online_users_limits_refresh_to_visible_user_ids(self):
        with self.app.app_context():
            other_server = Server(
                name='SrvOther',
                ip='127.0.0.2',
                port=22,
                ssh_user='root',
                description='server other',
            )
            other_server.ssh_password = 'rootpass'
            db.session.add(other_server)
            db.session.flush()

            other_user = VpnUser(
                username='USUARIO-OTRO',
                password='clave456',
                connection_limit=1,
                expiry_date=datetime.utcnow() + timedelta(days=30),
                reseller_id=self.reseller.id,
                server_id=other_server.id,
                is_active=True,
                is_blocked=False,
            )
            db.session.add(other_user)
            db.session.commit()

            selected_snapshot = {
                'online_map': {self.username: 1},
                'device_map': {self.username: 1},
                'connected_seconds_map': {self.username: 45},
            }

        login_response = self.client.post(
            '/login',
            data={'username': 'VPNPro', 'password': '123456'},
            follow_redirects=False,
        )
        self.assertEqual(login_response.status_code, 302)

        seen_server_ids = []

        def _fake_snapshot(server_id):
            seen_server_ids.append(server_id)
            if server_id == self.server.id:
                return selected_snapshot
            raise AssertionError('No debe consultar snapshots de servidores fuera de la tabla visible')

        with patch('routes.admin.get_cached_online_snapshot', side_effect=_fake_snapshot):
            response = self.client.get(f'/admin/users/online?user_ids={self.user_id}')

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload['ok'])
        self.assertEqual(seen_server_ids, [self.server.id])
        self.assertEqual(payload['online'], {
            str(self.user_id): {
                'sessions': 1,
                'limit': 1,
                'connected_seconds': 45,
            }
        })

    def test_admin_block_route_rejects_when_storage_is_critical(self):
        class _FakeCriticalSSHService(_FakeSSHService):
            def get_root_storage_status(self):
                return True, {
                    'blocks': '/dev/sda1 72000000 72000000 0 100% /',
                    'inodes': '/dev/sda1 1000000 10000 990000 1% /',
                    'blocks_used_percent': 100,
                    'inodes_used_percent': 1,
                }, ''

        login_response = self.client.post(
            '/login',
            data={'username': 'VPNPro', 'password': '123456'},
            follow_redirects=False,
        )
        self.assertEqual(login_response.status_code, 302)

        with patch('routes.admin.SSHService', _FakeCriticalSSHService):
            response = self.client.post(
                f'/admin/users/{self.user_id}/block',
                headers={'X-Requested-With': 'XMLHttpRequest'},
            )

        self.assertEqual(response.status_code, 400)
        payload = response.get_json()
        self.assertFalse(payload['ok'])
        self.assertIn('almacenamiento crítico', payload['message'].lower())

    def test_admin_delete_route_rejects_when_storage_is_critical(self):
        class _FakeCriticalSSHService(_FakeSSHService):
            def delete_user(self, username: str):
                raise AssertionError('delete_user no debe ejecutarse cuando el disco está crítico')

            def get_root_storage_status(self):
                return True, {
                    'blocks': '/dev/sda1 72000000 72000000 0 100% /',
                    'inodes': '/dev/sda1 1000000 10000 990000 1% /',
                    'blocks_used_percent': 100,
                    'inodes_used_percent': 1,
                }, ''

        login_response = self.client.post(
            '/login',
            data={'username': 'VPNPro', 'password': '123456'},
            follow_redirects=False,
        )
        self.assertEqual(login_response.status_code, 302)

        with patch('routes.admin.SSHService', _FakeCriticalSSHService):
            response = self.client.post(
                f'/admin/users/{self.user_id}/delete',
                headers={'X-Requested-With': 'XMLHttpRequest'},
            )

        self.assertEqual(response.status_code, 400)
        payload = response.get_json()
        self.assertFalse(payload['ok'])
        self.assertIn('almacenamiento crítico', payload['message'].lower())

    def test_admin_delete_route_rejects_when_inodes_are_critical(self):
        class _FakeInodeCriticalSSHService(_FakeSSHService):
            def delete_user(self, username: str):
                raise AssertionError('delete_user no debe ejecutarse cuando el disco está crítico')

            def get_root_storage_status(self):
                return True, {
                    'blocks': '/dev/sda1 72000000 36000000 36000000 50% /',
                    'inodes': '/dev/sda1 1000000 1000000 0 100% /',
                    'blocks_used_percent': 50,
                    'inodes_used_percent': 100,
                }, ''

        login_response = self.client.post(
            '/login',
            data={'username': 'VPNPro', 'password': '123456'},
            follow_redirects=False,
        )
        self.assertEqual(login_response.status_code, 302)

        with patch('routes.admin.SSHService', _FakeInodeCriticalSSHService):
            response = self.client.post(
                f'/admin/users/{self.user_id}/delete',
                headers={'X-Requested-With': 'XMLHttpRequest'},
            )

        self.assertEqual(response.status_code, 400)
        payload = response.get_json()
        self.assertFalse(payload['ok'])
        self.assertIn('almacenamiento crítico', payload['message'].lower())

    def test_admin_user_diagnostics_returns_json(self):
        login_response = self.client.post(
            '/login',
            data={'username': 'VPNPro', 'password': '123456'},
            follow_redirects=False,
        )
        self.assertEqual(login_response.status_code, 302)

        with patch('routes.admin.SSHService', _FakeSSHService):
            response = self.client.get(f'/admin/users/{self.user_id}/diagnostics')

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload['ok'])
        self.assertEqual(payload['username'], self.username)
        self.assertIn('checks', payload['details'])

    def test_reseller_user_diagnostics_returns_json(self):
        login_response = self.client.post(
            '/login',
            data={'username': 'reseller_test', 'password': 'resellerpass'},
            follow_redirects=False,
        )
        self.assertEqual(login_response.status_code, 302)

        with patch('routes.reseller.SSHService', _FakeSSHService):
            response = self.client.get(f'/reseller/users/{self.user_id}/diagnostics')

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload['ok'])
        self.assertEqual(payload['username'], self.username)
        self.assertIn('checks', payload['details'])


class DeleteServerTransferRegressionTestCase(unittest.TestCase):
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

            source = Server(name='Servidor 2', ip='10.0.0.2', port=22, ssh_user='root')
            source.ssh_password = 'rootpass'
            target = Server(name='Servidor 1', ip='10.0.0.1', port=22, ssh_user='root')
            target.ssh_password = 'rootpass'
            db.session.add_all([source, target])
            db.session.flush()

            source_reseller = Reseller(
                username='RESELLER-SOURCE',
                email='src@test.local',
                server_id=source.id,
                max_connections=2,
                panel_credits=0,
                is_active=True,
            )
            source_reseller.set_password('resellerpass')

            source_admin_owner = Reseller(
                username=f'Admin-{source.id}',
                email='system@local',
                server_id=source.id,
                max_connections=9999,
                panel_credits=0,
                is_active=False,
                note=SYSTEM_ADMIN_RESELLER_NOTE,
            )
            source_admin_owner.set_password('systempass')
            db.session.add_all([source_reseller, source_admin_owner])
            db.session.flush()

            reseller_user = VpnUser(
                username='USER-RESELLER',
                password='clave123',
                connection_limit=1,
                expiry_date=datetime.utcnow() + timedelta(days=30),
                reseller_id=source_reseller.id,
                server_id=source.id,
                is_active=True,
                is_blocked=False,
            )
            admin_owner_user = VpnUser(
                username='USER-ADMIN',
                password='clave123',
                connection_limit=1,
                expiry_date=datetime.utcnow() + timedelta(days=30),
                reseller_id=source_admin_owner.id,
                server_id=source.id,
                is_active=True,
                is_blocked=False,
            )
            db.session.add_all([reseller_user, admin_owner_user])
            db.session.commit()

            self.source_id = source.id
            self.target_id = target.id
            self.source_admin_owner_id = source_admin_owner.id
            self.admin_owner_user_id = admin_owner_user.id


class SharedUtilsHelpersTestCase(unittest.TestCase):
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
                name='SrvHelpers',
                ip='127.0.0.1',
                port=22,
                ssh_user='root',
                description='helpers test',
            )
            self.server.ssh_password = 'rootpass'
            db.session.add(self.server)
            db.session.flush()

            self.reseller = Reseller(
                username='HELPER-RESELLER',
                email='helpers@test.local',
                server_id=self.server.id,
                max_connections=2,
                panel_credits=10,
                is_active=True,
            )
            self.reseller.set_password('resellerpass')
            db.session.add(self.reseller)
            db.session.flush()

            self.user = VpnUser(
                username='USUARIO-HELPER',
                password='clave123',
                connection_limit=3,
                expiry_date=datetime.utcnow() + timedelta(days=15),
                reseller_id=self.reseller.id,
                server_id=self.server.id,
                is_active=True,
                is_blocked=False,
            )
            db.session.add(self.user)
            db.session.commit()

            self.user_id = self.user.id

    def _get_user(self):
        with self.app.app_context():
            return db.session.get(VpnUser, self.user_id)

    def test_serialize_user_for_ui_returns_expected_base_fields(self):
        user = self._get_user()
        payload = serialize_user_for_ui(user)

        self.assertEqual(payload['id'], user.id)
        self.assertEqual(payload['username'], 'USUARIO-HELPER')
        self.assertEqual(payload['password'], 'clave123')
        self.assertEqual(payload['connection_limit'], 3)
        self.assertFalse(payload['is_blocked'])
        self.assertFalse(payload['is_expired'])
        self.assertIn('expiry_date', payload)
        self.assertIn('expiry_datetime', payload)

    def test_respond_user_action_returns_ajax_json_with_custom_serializer(self):
        user = self._get_user()

        with self.app.test_request_context(
            '/admin/users/create',
            method='POST',
            headers={'X-Requested-With': 'XMLHttpRequest'},
        ):
            response, status_code = respond_user_action(
                'admin.users',
                'Operacion completada.',
                'success',
                ok=True,
                user=user,
                status_code=201,
                user_serializer=lambda current: {
                    'id': int(current.id),
                    'username': current.username,
                    'server_name': current.server.name if current.server else 'N/A',
                },
            )

        self.assertEqual(status_code, 201)
        payload = response.get_json()
        self.assertEqual(payload['message'], 'Operacion completada.')
        self.assertTrue(payload['ok'])
        self.assertEqual(payload['user']['username'], 'USUARIO-HELPER')
        self.assertEqual(payload['user']['server_name'], 'SrvHelpers')

    def test_respond_user_action_redirects_for_non_ajax_requests(self):
        with self.app.test_request_context('/admin/users/create', method='POST'):
            response = respond_user_action(
                'admin.dashboard',
                'Guardado.',
                'success',
                ok=True,
            )

        self.assertEqual(response.status_code, 302)
        self.assertIn('/admin/', response.location)

    def test_cache_get_returns_value_before_expiry_and_none_after_expiry(self):
        cache_key = 'test-shared-utils-cache'

        with patch('routes.shared_utils.time.monotonic', side_effect=[100.0, 100.5, 102.1]):
            cache_set(cache_key, 1, {'ok': True})
            self.assertEqual(cache_get(cache_key), {'ok': True})
            self.assertIsNone(cache_get(cache_key))

    def test_compose_action_error_adds_prefix_when_missing(self):
        msg = compose_action_error('bloquear usuario', 'No se pudo conectar: timeout')
        self.assertEqual(msg, 'Error al bloquear usuario: No se pudo conectar: timeout')

    def test_compose_action_error_avoids_duplicate_prefix(self):
        msg = compose_action_error('bloquear usuario', 'Error al bloquear usuario: permiso denegado')
        self.assertEqual(msg, 'Error al bloquear usuario: permiso denegado')

    def test_transfer_server_records_keeps_reseller_id_not_null(self):
        with self.app.app_context():
            source = db.session.get(Server, self.source_id)
            target = db.session.get(Server, self.target_id)

            ok, stats, err, _payloads = _transfer_server_records_db_only(source, target)
            self.assertTrue(ok, err)

            # Regression guard: this flush used to fail with NOT NULL on vpn_users.reseller_id.
            db.session.flush()
            # Additional guard: commit must not fail with stale rowcount mismatch on resellers.
            db.session.commit()

            null_reseller_refs = VpnUser.query.filter(VpnUser.reseller_id.is_(None)).count()
            self.assertEqual(null_reseller_refs, 0)

            target_admin_owner = Reseller.query.filter_by(
                server_id=self.target_id,
                note=SYSTEM_ADMIN_RESELLER_NOTE,
            ).first()
            self.assertIsNotNone(target_admin_owner)

            moved_admin_user = db.session.get(VpnUser, self.admin_owner_user_id)
            self.assertIsNotNone(moved_admin_user)
            self.assertEqual(moved_admin_user.reseller_id, target_admin_owner.id)

            deleted_source_admin_owner = db.session.get(Reseller, self.source_admin_owner_id)
            self.assertIsNone(deleted_source_admin_owner)
            self.assertGreaterEqual(stats.get('admin_users', 0), 1)


class DeleteResellerLegacyOwnerNameRegressionTestCase(unittest.TestCase):
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

            server = Server(name='Servidor Legacy', ip='10.10.10.10', port=22, ssh_user='root')
            server.ssh_password = 'rootpass'
            db.session.add(server)
            db.session.flush()

            legacy_reseller = Reseller(
                username=f'Admin-{server.id}',
                email='legacy@test.local',
                server_id=server.id,
                max_connections=2,
                panel_credits=0,
                is_active=True,
                note=None,
            )
            legacy_reseller.set_password('legacypass')
            db.session.add(legacy_reseller)
            db.session.flush()

            user = VpnUser(
                username='USER-LEGACY',
                password='clave123',
                connection_limit=1,
                expiry_date=datetime.utcnow() + timedelta(days=7),
                reseller_id=legacy_reseller.id,
                server_id=server.id,
                is_active=True,
                is_blocked=False,
            )
            db.session.add(user)
            db.session.commit()

            self.server_id = server.id
            self.legacy_reseller_id = legacy_reseller.id
            self.user_id = user.id

        self.client = self.app.test_client()

    def test_delete_reseller_reassigns_users_even_with_reserved_legacy_username(self):
        login_response = self.client.post(
            '/login',
            data={'username': 'VPNPro', 'password': '123456'},
            follow_redirects=False,
        )
        self.assertEqual(login_response.status_code, 302)

        response = self.client.post(
            f'/admin/resellers/{self.legacy_reseller_id}/delete',
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)

        with self.app.app_context():
            deleted = db.session.get(Reseller, self.legacy_reseller_id)
            self.assertIsNone(deleted)

            internal_owner = Reseller.query.filter_by(
                server_id=self.server_id,
                note=SYSTEM_ADMIN_RESELLER_NOTE,
            ).first()
            self.assertIsNotNone(internal_owner)

            moved_user = db.session.get(VpnUser, self.user_id)
            self.assertIsNotNone(moved_user)
            self.assertEqual(moved_user.reseller_id, internal_owner.id)


class BackupRestoreDeletedUserRegressionTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix='vpnpro-backup-restore-')
        self.db_path = os.path.join(self.temp_dir, 'vpnpro.db')
        self.original_instance_dir = Config.INSTANCE_DIR
        self.original_db_uri = Config.SQLALCHEMY_DATABASE_URI
        self.original_secret_key = Config.SECRET_KEY
        self.original_encryption_key = Config.ENCRYPTION_KEY

        Config.INSTANCE_DIR = self.temp_dir
        Config.SQLALCHEMY_DATABASE_URI = f'sqlite:///{self.db_path}'
        Config.SECRET_KEY = 'test-secret-key'
        Config.ENCRYPTION_KEY = Fernet.generate_key()

        with open(os.path.join(self.temp_dir, '.enc_key'), 'wb') as fh:
            fh.write(Config.ENCRYPTION_KEY)

        self.app = create_app()
        self.app.config.update(
            TESTING=True,
            WTF_CSRF_ENABLED=False,
            AUTO_SYNC_ENABLED=False,
            AUTO_LIMITER_ENABLED=False,
        )

        with self.app.app_context():
            db.drop_all()
            db.create_all()

            server = Server(name='SrvBackup', ip='127.0.0.1', port=22, ssh_user='root')
            server.ssh_password = 'rootpass'
            db.session.add(server)
            db.session.flush()

            reseller = Reseller(
                username='reseller_backup',
                email='backup@test.local',
                server_id=server.id,
                max_connections=5,
                panel_credits=0,
                is_active=True,
            )
            reseller.set_password('resellerpass')
            db.session.add(reseller)
            db.session.flush()

            user = VpnUser(
                username='RESTORE-ME',
                password='clave123',
                connection_limit=1,
                expiry_date=datetime.utcnow() + timedelta(days=30),
                reseller_id=reseller.id,
                server_id=server.id,
                is_active=True,
                is_blocked=False,
            )
            db.session.add(user)
            db.session.commit()

        self.client = self.app.test_client()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()
            db.engine.dispose()

        Config.INSTANCE_DIR = self.original_instance_dir
        Config.SQLALCHEMY_DATABASE_URI = self.original_db_uri
        Config.SECRET_KEY = self.original_secret_key
        Config.ENCRYPTION_KEY = self.original_encryption_key
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_restore_recovers_user_deleted_after_backup(self):
        login_response = self.client.post(
            '/login',
            data={'username': 'VPNPro', 'password': '123456'},
            follow_redirects=False,
        )
        self.assertEqual(login_response.status_code, 302)

        backup_response = self.client.post('/admin/backup/create', follow_redirects=False)
        self.assertEqual(backup_response.status_code, 200)

        with self.app.app_context():
            user = VpnUser.query.filter_by(username='RESTORE-ME').first()
            self.assertIsNotNone(user)
            db.session.delete(user)
            db.session.commit()

            deleted_user = VpnUser.query.filter_by(username='RESTORE-ME').first()
            self.assertIsNone(deleted_user)
            self.assertTrue(os.path.exists(self.db_path + '-wal'))

        restore_response = self.client.post(
            '/admin/backup/restore',
            data={'backup_file': (io.BytesIO(backup_response.data), 'vpnpro-backup.zip')},
            content_type='multipart/form-data',
            follow_redirects=False,
        )
        self.assertEqual(restore_response.status_code, 302)

        with self.app.app_context():
            db.session.remove()
            restored_user = VpnUser.query.filter_by(username='RESTORE-ME').first()
            self.assertIsNotNone(restored_user)


class _FakeAutoBlockSSHService:
    trimmed_usernames = []

    def connect(self):
        return True, 'ok'

    def disconnect(self):
        return None

    def trim_user_sessions(self, username: str, keep_sessions: int = 1):
        _FakeAutoBlockSSHService.trimmed_usernames.append((username, keep_sessions))
        return True, 1, 'Sesiones excedentes cerradas: 1'


class AutoTrimOnExcessTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config.update(
            TESTING=True,
            AUTO_SYNC_ENABLED=False,
            AUTO_TRIM_FIRST_STRIKE_LIMIT_ONE=False,
            SQLALCHEMY_DATABASE_URI='sqlite:///:memory:',
        )

        with self.app.app_context():
            db.drop_all()
            db.create_all()

            self.server = Server(
                name='SrvAutoBlock',
                ip='127.0.0.1',
                port=22,
                ssh_user='root',
                description='server test',
            )
            self.server.ssh_password = 'rootpass'
            db.session.add(self.server)
            db.session.flush()

            self.reseller = Reseller(
                username='reseller_autoblock',
                email='reseller_autoblock@test.local',
                server_id=self.server.id,
                max_connections=2,
                panel_credits=20,
                is_active=True,
            )
            self.reseller.set_password('resellerpass')
            db.session.add(self.reseller)
            db.session.flush()

            self.user = VpnUser(
                username='USUARIO-INSISTENTE',
                password='clave123',
                connection_limit=1,
                expiry_date=datetime.utcnow() + timedelta(days=30),
                reseller_id=self.reseller.id,
                server_id=self.server.id,
                is_active=True,
                is_blocked=False,
            )
            db.session.add(self.user)
            db.session.commit()

            self.user_id = self.user.id

    def test_trim_when_session_count_exceeds_limit(self):
        _FakeAutoBlockSSHService.trimmed_usernames = []

        with self.app.app_context():
            user_rows = [
                (self.user_id, 'USUARIO-INSISTENTE', 1, False),
            ]

            online_map = {'USUARIO-INSISTENTE': 3}
            svc = _FakeAutoBlockSSHService()

            with patch('routes.shared_utils.time.monotonic', return_value=1000.0):
                trimmed_1, errors_1 = auto_block_users_exceeding_limit(user_rows, online_map, svc)
            with patch('routes.shared_utils.time.monotonic', return_value=1005.0):
                trimmed_2, errors_2 = auto_block_users_exceeding_limit(user_rows, online_map, svc)

            self.assertEqual(trimmed_1, [])
            self.assertEqual(errors_1, [])
            self.assertEqual(trimmed_2, ['USUARIO-INSISTENTE'])
            self.assertEqual(errors_2, [])

            user_db = db.session.get(VpnUser, self.user_id)
            self.assertIsNotNone(user_db)
            self.assertFalse(user_db.is_blocked)
            self.assertEqual(_FakeAutoBlockSSHService.trimmed_usernames, [('USUARIO-INSISTENTE', 1)])

    def test_trim_when_device_count_exceeds_limit(self):
        _FakeAutoBlockSSHService.trimmed_usernames = []

        with self.app.app_context():
            user_rows = [
                (self.user_id, 'USUARIO-INSISTENTE', 1, False),
            ]

            online_map = {'USUARIO-INSISTENTE': 1}
            device_online_map = {'USUARIO-INSISTENTE': 3}
            svc = _FakeAutoBlockSSHService()

            with patch('routes.shared_utils.time.monotonic', return_value=1000.0):
                trimmed_1, errors_1 = auto_block_users_exceeding_limit(
                    user_rows,
                    online_map,
                    svc,
                    device_online_map=device_online_map,
                )
            with patch('routes.shared_utils.time.monotonic', return_value=1005.0):
                trimmed_2, errors_2 = auto_block_users_exceeding_limit(
                    user_rows,
                    online_map,
                    svc,
                    device_online_map=device_online_map,
                )

            self.assertEqual(trimmed_1, [])
            self.assertEqual(errors_1, [])
            self.assertEqual(trimmed_2, ['USUARIO-INSISTENTE'])
            self.assertEqual(errors_2, [])

            user_db = db.session.get(VpnUser, self.user_id)
            self.assertIsNotNone(user_db)
            self.assertFalse(user_db.is_blocked)
            self.assertEqual(_FakeAutoBlockSSHService.trimmed_usernames, [('USUARIO-INSISTENTE', 1)])

    def test_limit_one_trims_after_consecutive_detection(self):
        _FakeAutoBlockSSHService.trimmed_usernames = []

        with self.app.app_context():
            user_rows = [
                (self.user_id, 'USUARIO-INSISTENTE', 1, False),
            ]

            online_map = {'USUARIO-INSISTENTE': 2}
            device_online_map = {'USUARIO-INSISTENTE': 2}
            svc = _FakeAutoBlockSSHService()

            with patch('routes.shared_utils.time.monotonic', return_value=1000.0):
                trimmed_1, errors_1 = auto_block_users_exceeding_limit(
                    user_rows,
                    online_map,
                    svc,
                    device_online_map=device_online_map,
                )

            with patch('routes.shared_utils.time.monotonic', return_value=1005.0):
                trimmed_2, errors_2 = auto_block_users_exceeding_limit(
                    user_rows,
                    online_map,
                    svc,
                    device_online_map=device_online_map,
                )

            self.assertEqual(trimmed_1, [])
            self.assertEqual(errors_1, [])
            self.assertEqual(trimmed_2, ['USUARIO-INSISTENTE'])
            self.assertEqual(errors_2, [])
            self.assertEqual(_FakeAutoBlockSSHService.trimmed_usernames, [('USUARIO-INSISTENTE', 1)])

    def test_wifi_to_mobile_limit_one_trims_immediately_with_first_strike(self):
        _FakeAutoBlockSSHService.trimmed_usernames = []

        with self.app.app_context():
            self.app.config['AUTO_TRIM_FIRST_STRIKE_LIMIT_ONE'] = True
            user_rows = [
                (self.user_id, 'DIEGO-PINTO', 1, False),
            ]

            # Escenario: sesión inicial en WiFi y reconexión en red móvil.
            # El detector observa 2 sesiones/2 peers para el mismo usuario.
            online_map = {'DIEGO-PINTO': 2}
            device_online_map = {'DIEGO-PINTO': 2}
            svc = _FakeAutoBlockSSHService()

            with patch('routes.shared_utils.time.monotonic', return_value=2000.0):
                trimmed, errors = auto_block_users_exceeding_limit(
                    user_rows,
                    online_map,
                    svc,
                    device_online_map=device_online_map,
                )

            self.assertEqual(trimmed, ['DIEGO-PINTO'])
            self.assertEqual(errors, [])
            self.assertEqual(_FakeAutoBlockSSHService.trimmed_usernames, [('DIEGO-PINTO', 1)])

    def test_limit_one_same_nat_still_trims_immediately_with_first_strike(self):
        _FakeAutoBlockSSHService.trimmed_usernames = []

        with self.app.app_context():
            self.app.config['AUTO_TRIM_FIRST_STRIKE_LIMIT_ONE'] = True
            user_rows = [
                (self.user_id, 'DIEGO-PINTO', 1, False),
            ]

            online_map = {'DIEGO-PINTO': 2}
            device_online_map = {'DIEGO-PINTO': 1}
            svc = _FakeAutoBlockSSHService()

            with patch('routes.shared_utils.time.monotonic', return_value=2100.0):
                trimmed, errors = auto_block_users_exceeding_limit(
                    user_rows,
                    online_map,
                    svc,
                    device_online_map=device_online_map,
                )

            self.assertEqual(trimmed, ['DIEGO-PINTO'])
            self.assertEqual(errors, [])
            self.assertEqual(_FakeAutoBlockSSHService.trimmed_usernames, [('DIEGO-PINTO', 1)])

    def test_wifi_to_mobile_limit_one_requires_second_detection_when_flag_disabled(self):
        _FakeAutoBlockSSHService.trimmed_usernames = []

        with self.app.app_context():
            self.app.config['AUTO_TRIM_FIRST_STRIKE_LIMIT_ONE'] = False
            user_rows = [
                (self.user_id, 'DIEGO-PINTO', 1, False),
            ]

            online_map = {'DIEGO-PINTO': 2}
            device_online_map = {'DIEGO-PINTO': 2}
            svc = _FakeAutoBlockSSHService()

            with patch('routes.shared_utils.time.monotonic', return_value=3000.0):
                trimmed_1, errors_1 = auto_block_users_exceeding_limit(
                    user_rows,
                    online_map,
                    svc,
                    device_online_map=device_online_map,
                )

            with patch('routes.shared_utils.time.monotonic', return_value=3005.0):
                trimmed_2, errors_2 = auto_block_users_exceeding_limit(
                    user_rows,
                    online_map,
                    svc,
                    device_online_map=device_online_map,
                )

            self.assertEqual(trimmed_1, [])
            self.assertEqual(errors_1, [])
            self.assertEqual(trimmed_2, ['DIEGO-PINTO'])
            self.assertEqual(errors_2, [])
            self.assertEqual(_FakeAutoBlockSSHService.trimmed_usernames, [('DIEGO-PINTO', 1)])

    def test_limit_one_does_not_retrim_during_cooldown(self):
        _FakeAutoBlockSSHService.trimmed_usernames = []

        with self.app.app_context():
            user_rows = [
                (self.user_id, 'USUARIO-INSISTENTE', 1, False),
            ]

            online_map = {'USUARIO-INSISTENTE': 2}
            device_online_map = {'USUARIO-INSISTENTE': 2}
            svc = _FakeAutoBlockSSHService()

            with patch('routes.shared_utils.time.monotonic', return_value=1000.0):
                trimmed_1, errors_1 = auto_block_users_exceeding_limit(
                    user_rows,
                    online_map,
                    svc,
                    device_online_map=device_online_map,
                )

            with patch('routes.shared_utils.time.monotonic', return_value=1005.0):
                trimmed_2, errors_2 = auto_block_users_exceeding_limit(
                    user_rows,
                    online_map,
                    svc,
                    device_online_map=device_online_map,
                )

            with patch('routes.shared_utils.time.monotonic', return_value=1010.0):
                trimmed_3, errors_3 = auto_block_users_exceeding_limit(
                    user_rows,
                    online_map,
                    svc,
                    device_online_map=device_online_map,
                )

            self.assertEqual(trimmed_1, [])
            self.assertEqual(errors_1, [])
            self.assertEqual(trimmed_2, ['USUARIO-INSISTENTE'])
            self.assertEqual(errors_2, [])
            self.assertEqual(trimmed_3, [])
            self.assertEqual(errors_3, [])
            self.assertEqual(
                _FakeAutoBlockSSHService.trimmed_usernames,
                [('USUARIO-INSISTENTE', 1)],
            )

    def test_trims_when_two_sessions_same_nat_ip(self):
        """2 sesiones desde el mismo NAT/IP deben recortarse al segundo ciclo.

        Con limite=1, observed = max(sessions=2, devices=1) = 2 > 1.
        El primer ciclo establece la confirmación; el segundo (dentro del TTL) recorta.
        """
        _FakeAutoBlockSSHService.trimmed_usernames = []

        with self.app.app_context():
            user_rows = [
                (self.user_id, 'USUARIO-INSISTENTE', 1, False),
            ]

            # Dos sesiones SSH desde la misma IP/NAT: sessions=2, devices=1.
            # max(2, 1) = 2 > limit=1 → debe recortar tras confirmar.
            online_map = {'USUARIO-INSISTENTE': 2}
            device_online_map = {'USUARIO-INSISTENTE': 1}
            svc = _FakeAutoBlockSSHService()

            with patch('routes.shared_utils.time.monotonic', return_value=1000.0):
                trimmed_1, errors_1 = auto_block_users_exceeding_limit(
                    user_rows,
                    online_map,
                    svc,
                    device_online_map=device_online_map,
                )

            self.assertEqual(trimmed_1, [])
            self.assertEqual(errors_1, [])
            self.assertEqual(_FakeAutoBlockSSHService.trimmed_usernames, [])

            # Segundo ciclo dentro de la ventana de confirmación (5s < 8s TTL) → recorta.
            with patch('routes.shared_utils.time.monotonic', return_value=1005.0):
                trimmed_2, errors_2 = auto_block_users_exceeding_limit(
                    user_rows,
                    online_map,
                    svc,
                    device_online_map=device_online_map,
                )

            self.assertEqual(trimmed_2, ['USUARIO-INSISTENTE'])
            self.assertEqual(errors_2, [])
            self.assertEqual(_FakeAutoBlockSSHService.trimmed_usernames, [('USUARIO-INSISTENTE', 1)])


if __name__ == '__main__':
    unittest.main()
