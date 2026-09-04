import os
import re
import threading
import time
import traceback

try:
    import fcntl
except Exception:  # pragma: no cover - Windows y entornos sin fcntl
    fcntl = None

from flask import Flask, redirect, url_for
from flask_login import LoginManager, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import text
from models import db, Admin, Reseller, Server, VpnUser
from config import Config

try:
    from flask_compress import Compress
except Exception:  # pragma: no cover - fallback si dependencia no está disponible aún
    Compress = None

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

_SERVER_NAME_NUMBER_RE = re.compile(r'\d+')


def _server_logical_sort_key(server: Server) -> tuple[int, int, str, int]:
    """Natural sort by first number in server name, then by name/id."""
    raw_name = (server.name or '').strip()
    lowered = raw_name.lower()
    match = _SERVER_NAME_NUMBER_RE.search(lowered)
    if match:
        return 0, int(match.group(0)), lowered, int(server.id or 0)
    return 1, 0, lowered, int(server.id or 0)


def _get_restore_lock(app: Flask) -> threading.Lock:
    lock = app.extensions.get('db_restore_lock')
    if lock is not None:
        return lock
    new_lock = threading.Lock()
    app.extensions['db_restore_lock'] = new_lock
    return new_lock


def _is_background_worker_leader(app: Flask) -> bool:
    cached = app.extensions.get('background_worker_leader')
    if cached is not None:
        return bool(cached)

    if fcntl is None:
        app.extensions['background_worker_leader'] = True
        return True

    os.makedirs(app.instance_path, exist_ok=True)
    lock_path = os.path.join(app.instance_path, '.background-workers.lock')
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        app.extensions['background_worker_leader'] = False
        return False
    except Exception:
        os.close(fd)
        # Fallback seguro para no dejar despliegues sin workers automáticos.
        app.extensions['background_worker_leader'] = True
        return True

    app.extensions['background_worker_lock_fd'] = fd
    app.extensions['background_worker_leader'] = True
    return True


def _start_connection_limiter_worker(app: Flask) -> None:
    if not app.config.get('AUTO_LIMITER_ENABLED', True):
        app.logger.info('Limitador de conexiones en background deshabilitado por configuracion.')
        return

    default_interval_seconds = max(
        2,
        int(
            app.config.get(
                'AUTO_LIMITER_INTERVAL_SECONDS',
                max(2, int(app.config.get('ONLINE_CHECK_INTERVAL_MS', 60000) / 1000)),
            )
        ),
    )
    restore_lock = _get_restore_lock(app)

    def _worker() -> None:
        from routes.shared_utils import auto_block_users_exceeding_limit
        from routes.shared_utils import cache_online_snapshot
        from routes.shared_utils import get_limiter_interval_seconds
        from services.ssh_service import SSHService

        app.logger.info('Limitador de conexiones en background iniciado cada %s segundo(s).', default_interval_seconds)
        last_guard_log_at = 0.0
        last_interval_logged = 0
        while True:
            interval_seconds = default_interval_seconds
            try:
                with app.app_context():
                    interval_seconds = max(2, int(get_limiter_interval_seconds()))
            except Exception:
                interval_seconds = default_interval_seconds

            if interval_seconds != last_interval_logged:
                app.logger.info('Limitador background usando intervalo actual de %s segundo(s).', interval_seconds)
                last_interval_logged = interval_seconds

            time.sleep(interval_seconds)
            try:
                with restore_lock:
                    with app.app_context():
                        guard_until = float(app.extensions.get('restore_guard_until', 0.0) or 0.0)
                        if guard_until > time.time():
                            now = time.time()
                            if now - last_guard_log_at >= 30:
                                remaining = max(0, int(guard_until - now))
                                app.logger.info(
                                    '[RESTORE-GUARD] Limitador background en pausa (%ss restantes).',
                                    remaining,
                                )
                                last_guard_log_at = now
                            continue

                        active_users = (
                            db.session.query(
                                VpnUser.id,
                                VpnUser.server_id,
                                VpnUser.username,
                                VpnUser.connection_limit,
                                VpnUser.is_blocked,
                            )
                            .filter(VpnUser.is_active.is_(True))
                            .all()
                        )
                        if not active_users:
                            continue

                        users_by_server: dict[int, list[tuple[int, str, int, bool]]] = {}
                        for user_id, server_id, username, connection_limit, is_blocked in active_users:
                            users_by_server.setdefault(server_id, []).append((user_id, username, connection_limit, is_blocked))

                        servers_map: dict[int, Server] = {
                            s.id: s for s in Server.query.filter(Server.id.in_(list(users_by_server.keys()))).all()
                        }

                        trimmed_total = 0
                        errors: list[str] = []

                        for server_id, server_users in users_by_server.items():
                            server = servers_map.get(server_id)
                            if not server:
                                continue

                            svc = SSHService(server)
                            ok, online_map, device_map, connected_seconds_map, err = svc.get_online_user_snapshot()
                            if not ok:
                                errors.append(f'{server.name}: {err}')
                                continue

                            normalized_devices = {k.strip().upper(): v for k, v in (device_map or {}).items()}
                            cache_online_snapshot(
                                server_id,
                                online_map,
                                device_map=normalized_devices,
                                connected_seconds_map=connected_seconds_map,
                            )

                            normalized = {k.strip().upper(): v for k, v in (online_map or {}).items()}
                            trimmed_now, block_errors = auto_block_users_exceeding_limit(
                                server_users,
                                normalized,
                                svc,
                                device_online_map=normalized_devices,
                            )

                            trimmed_total += len(trimmed_now)
                            if trimmed_now:
                                ok_refresh, refreshed_online_map, refreshed_device_map, refreshed_connected_seconds_map, refresh_err = svc.get_online_user_snapshot()
                                if ok_refresh:
                                    normalized = {k.strip().upper(): v for k, v in (refreshed_online_map or {}).items()}
                                else:
                                    errors.append(
                                        f'{server.name}: No se pudo refrescar sesiones tras control automatico: {refresh_err}'
                                    )

                                refreshed_normalized_devices = {
                                    k.strip().upper(): v for k, v in (refreshed_device_map or {}).items()
                                }

                                cache_online_snapshot(
                                    server_id,
                                    normalized,
                                    device_map=refreshed_normalized_devices,
                                    connected_seconds_map=refreshed_connected_seconds_map,
                                )
                            if block_errors:
                                errors.extend([f'{server.name}: {detail}' for detail in block_errors])

                        if trimmed_total:
                            app.logger.warning(
                                'Limitador background aplicado: sesiones_recortadas=%s',
                                trimmed_total,
                            )
                        if errors:
                            for detail in errors[:10]:
                                app.logger.warning('Limitador background error: %s', detail)
            except Exception:
                with app.app_context():
                    db.session.rollback()
                app.logger.exception('Limitador background: error inesperado')

    thread = threading.Thread(target=_worker, name='vpnpro-auto-limiter', daemon=True)
    thread.start()


def _start_auto_sync_worker(app: Flask) -> None:
    if not app.config.get('AUTO_SYNC_ENABLED', True):
        app.logger.info('Auto-sync deshabilitado por configuracion.')
        return

    interval_min = max(1, int(app.config.get('AUTO_SYNC_INTERVAL_MINUTES', 30)))
    restore_lock = _get_restore_lock(app)

    def _worker() -> None:
        from routes.admin import _sync_server_users_data

        app.logger.info('Auto-sync iniciado cada %s minuto(s).', interval_min)
        last_guard_log_at = 0.0
        while True:
            time.sleep(interval_min * 60)
            try:
                with restore_lock:
                    with app.app_context():
                        guard_until = float(app.extensions.get('restore_guard_until', 0.0) or 0.0)
                        if guard_until > time.time():
                            now = time.time()
                            if now - last_guard_log_at >= 30:
                                remaining = max(0, int(guard_until - now))
                                app.logger.info(
                                    '[RESTORE-GUARD] Auto-sync en pausa (%ss restantes).',
                                    remaining,
                                )
                                last_guard_log_at = now
                            continue

                        servers = Server.query.filter_by(is_active=True).all()
                        servers = sorted(servers, key=_server_logical_sort_key)
                        if not servers:
                            continue

                        ok_servers = 0
                        fail_servers = 0
                        total_panel = 0
                        total_pushed = 0
                        total_created_remote = 0
                        total_updated_remote = 0
                        total_deleted_remote = 0
                        total_deduped_panel = 0
                        total_failed_ops = 0

                        for server in servers:
                            ok, stats, err = _sync_server_users_data(server, delete_remote=False)
                            if not ok:
                                fail_servers += 1
                                app.logger.warning(
                                    'Auto-sync fallo en servidor %s (%s): %s',
                                    server.name,
                                    server.id,
                                    err,
                                )
                                continue

                            ok_servers += 1
                            total_panel += stats['panel_total']
                            total_pushed += stats['pushed']
                            total_created_remote += stats['created_remote']
                            total_updated_remote += stats['updated_remote']
                            total_deleted_remote += stats['deleted_remote']
                            total_deduped_panel += stats['deduped_panel']
                            total_failed_ops += stats.get('failed_ops', 0)

                        db.session.commit()
                        app.logger.info(
                            (
                                '[AUTO-SYNC] panel->VPS completado (sin borrado remoto): %s ok, %s con error | '
                                'aplicados=%s/%s, creados_vps=%s, actualizados_vps=%s, eliminados_vps=%s, deduplicados_panel=%s, errores_ops=%s'
                            ),
                            ok_servers,
                            fail_servers,
                            total_pushed,
                            total_panel,
                            total_created_remote,
                            total_updated_remote,
                            total_deleted_remote,
                            total_deduped_panel,
                            total_failed_ops,
                        )
            except Exception:
                with app.app_context():
                    db.session.rollback()
                app.logger.exception('Auto-sync error inesperado')

    thread = threading.Thread(target=_worker, name='vpnpro-auto-sync', daemon=True)
    thread.start()


def _start_disk_housekeeping_worker(app: Flask) -> None:
    if not app.config.get('AUTO_DISK_HOUSEKEEPING_ENABLED', True):
        app.logger.info('Housekeeping de disco deshabilitado por configuracion.')
        return

    interval_min = max(5, int(app.config.get('AUTO_DISK_HOUSEKEEPING_INTERVAL_MINUTES', 60) or 60))
    trigger_percent = max(50, int(app.config.get('DISK_HOUSEKEEPING_TRIGGER_PERCENT', 92) or 92))
    journal_max_mb = max(50, int(app.config.get('DISK_HOUSEKEEPING_JOURNAL_MAX_MB', 200) or 200))
    tmp_max_days = max(1, int(app.config.get('DISK_HOUSEKEEPING_TMP_MAX_AGE_DAYS', 3) or 3))

    restore_lock = _get_restore_lock(app)
    hardened_server_ids: set[int] = set()

    def _worker() -> None:
        from services.ssh_service import SSHService

        app.logger.info(
            'Housekeeping de disco iniciado cada %s minuto(s). Trigger=%s%%',
            interval_min,
            trigger_percent,
        )

        while True:
            time.sleep(interval_min * 60)
            try:
                with restore_lock:
                    with app.app_context():
                        servers = Server.query.filter_by(is_active=True).all()
                        servers = sorted(servers, key=_server_logical_sort_key)
                        if not servers:
                            continue

                        for server in servers:
                            svc = SSHService(server)

                            # Hardening permanente: solo una vez por servidor en este proceso.
                            if server.id not in hardened_server_ids:
                                ok_h, msg_h = svc.apply_disk_hardening()
                                if ok_h:
                                    hardened_server_ids.add(server.id)
                                    app.logger.info(
                                        '[DISK-HARDENING] %s (%s): %s',
                                        server.name,
                                        server.id,
                                        msg_h,
                                    )
                                else:
                                    app.logger.warning(
                                        '[DISK-HARDENING] %s (%s) fallo: %s',
                                        server.name,
                                        server.id,
                                        msg_h,
                                    )

                            ok, report, err = svc.run_disk_housekeeping(
                                trigger_percent=trigger_percent,
                                journal_max_mb=journal_max_mb,
                                tmp_max_age_days=tmp_max_days,
                            )
                            if not ok:
                                app.logger.warning(
                                    'Housekeeping disco fallo en %s (%s): %s',
                                    server.name,
                                    server.id,
                                    err,
                                )
                                continue

                            if not report.get('ran'):
                                continue

                            before = report.get('before') if isinstance(report.get('before'), dict) else {}
                            after = report.get('after') if isinstance(report.get('after'), dict) else {}
                            app.logger.info(
                                (
                                    '[DISK-HOUSEKEEPING] %s (%s): antes=%s%% despues=%s%% '
                                    'liberado=%spp'
                                ),
                                server.name,
                                server.id,
                                before.get('blocks_used_percent', 'N/A'),
                                after.get('blocks_used_percent', 'N/A'),
                                report.get('freed_percent_points', 0),
                            )
            except Exception:
                app.logger.exception('Housekeeping de disco: error inesperado')

    thread = threading.Thread(target=_worker, name='vpnpro-disk-housekeeping', daemon=True)
    thread.start()


def create_app() -> Flask:
    app = Flask(__name__, instance_path=Config.INSTANCE_DIR)
    app.config.from_object(Config)
    _get_restore_lock(app)
    app.extensions.setdefault('restore_guard_until', 0.0)
    app.config.setdefault('SEND_FILE_MAX_AGE_DEFAULT', int(os.environ.get('STATIC_CACHE_SECONDS', '604800')))
    app.config.setdefault('TEMPLATES_AUTO_RELOAD', False)

    if Compress is not None:
        app.config.setdefault('COMPRESS_ALGORITHM', ['br', 'gzip'])
        app.config.setdefault('COMPRESS_LEVEL', 6)
        app.config.setdefault('COMPRESS_MIN_SIZE', 700)
        Compress(app)

    db.init_app(app)
    limiter.init_app(app)

    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Por favor inicia sesión para acceder.'
    login_manager.login_message_category = 'warning'

    @login_manager.user_loader
    def load_user(user_id: str):
        if user_id.startswith('admin:'):
            return db.session.get(Admin, int(user_id.split(':')[1]))
        if user_id.startswith('reseller:'):
            return db.session.get(Reseller, int(user_id.split(':')[1]))
        return None

    from routes.auth import auth_bp
    from routes.admin import admin_bp
    from routes.reseller import reseller_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(reseller_bp, url_prefix='/reseller')

    # ── Teardown: ensure the session is always cleaned up ──────────────────
    @app.teardown_appcontext
    def _shutdown_session(exc):
        if exc is not None:
            db.session.rollback()
        db.session.remove()

    # ── Global error handlers ───────────────────────────────────────────────
    _ERROR_HTML = (
        '<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">'
        '<title>{title}</title>'
        '<style>body{{font-family:sans-serif;text-align:center;padding:4rem;color:#555}}'
        'h1{{font-size:2.5rem;color:#c0392b}}p{{margin-top:1rem}}'
        'a{{color:#2980b9;text-decoration:none}}</style></head>'
        '<body><h1>{code}</h1><p>{message}</p>'
        '<p><a href="/">← Volver al inicio</a></p></body></html>'
    )

    @app.errorhandler(404)
    def _handle_404(_exc):
        html = _ERROR_HTML.format(
            title='Página no encontrada',
            code='404',
            message='La página que buscas no existe.',
        )
        return html, 404

    @app.errorhandler(429)
    def _handle_429(_exc):
        html = _ERROR_HTML.format(
            title='Demasiadas solicitudes',
            code='429',
            message='Demasiados intentos. Por favor espera un momento.',
        )
        return html, 429

    @app.errorhandler(500)
    def _handle_500(exc):
        app.logger.error('Error interno 500: %s', exc, exc_info=True)
        try:
            db.session.rollback()
        except Exception:
            pass
        html = _ERROR_HTML.format(
            title='Error interno',
            code='500',
            message='Error interno del servidor. Por favor recarga la página o intenta de nuevo.',
        )
        return html, 500

    @app.errorhandler(Exception)
    def _handle_exception(exc):
        # Re-raise HTTP exceptions so Flask handles them normally
        from werkzeug.exceptions import HTTPException
        if isinstance(exc, HTTPException):
            return exc
        app.logger.error('Excepción no capturada: %s\n%s', exc, traceback.format_exc())
        try:
            db.session.rollback()
        except Exception:
            pass
        html = _ERROR_HTML.format(
            title='Error interno',
            code='500',
            message='Error interno del servidor. Por favor recarga la página o intenta de nuevo.',
        )
        return html, 500

    @app.route('/')
    def index():
        if current_user.is_authenticated:
            if isinstance(current_user, Admin):
                return redirect(url_for('admin.dashboard'))
            return redirect(url_for('reseller.dashboard'))
        return redirect(url_for('auth.login'))

    with app.app_context():
        os.makedirs(app.instance_path, exist_ok=True)
        db.create_all()

        if str(db.engine.url).startswith('sqlite:'):
            db.session.execute(text('PRAGMA journal_mode=WAL'))
            db.session.execute(text('PRAGMA synchronous=NORMAL'))
            db.session.execute(text('PRAGMA temp_store=MEMORY'))
            db.session.execute(text('PRAGMA busy_timeout=30000'))
            db.session.commit()

        # Lightweight runtime migration for existing SQLite deployments.
        cols = db.session.execute(text("PRAGMA table_info(resellers)")).fetchall()
        col_names = {c[1] for c in cols}
        if 'panel_credits' not in col_names:
            db.session.execute(text("ALTER TABLE resellers ADD COLUMN panel_credits INTEGER DEFAULT 0"))
            db.session.commit()
        
        if 'max_connections' not in col_names:
            db.session.execute(text("ALTER TABLE resellers ADD COLUMN max_connections INTEGER DEFAULT 0"))
            db.session.commit()

        admin_cols = db.session.execute(text("PRAGMA table_info(admins)")).fetchall()
        admin_col_names = {c[1] for c in admin_cols}
        if 'max_connections' not in admin_col_names:
            db.session.execute(text("ALTER TABLE admins ADD COLUMN max_connections INTEGER DEFAULT 0"))
            db.session.commit()

        user_cols = db.session.execute(text("PRAGMA table_info(vpn_users)")).fetchall()
        user_col_names = {c[1] for c in user_cols}
        if 'is_blocked' not in user_col_names:
            db.session.execute(text("ALTER TABLE vpn_users ADD COLUMN is_blocked INTEGER DEFAULT 0"))
            db.session.commit()

        server_cols = db.session.execute(text("PRAGMA table_info(servers)")).fetchall()
        server_col_names = {c[1] for c in server_cols}
        if 'timezone' not in server_col_names:
            db.session.execute(text("ALTER TABLE servers ADD COLUMN timezone VARCHAR(60) DEFAULT 'America/Bogota' NOT NULL"))
            db.session.commit()

        # Índices adicionales para acelerar listados y panel en despliegues existentes.
        db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_vpnuser_active_created ON vpn_users (is_active, created_at)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_vpnuser_server_active_created ON vpn_users (server_id, is_active, created_at)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_vpnuser_reseller_active_created ON vpn_users (reseller_id, is_active, created_at)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_vpnuser_active_block_expiry ON vpn_users (is_active, is_blocked, expiry_date)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_vpnuser_active_username ON vpn_users (is_active, username)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_reseller_note_active ON resellers (note, is_active)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_reseller_active_server_username ON resellers (is_active, server_id, username)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_reseller_email ON resellers (email)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_credit_created ON credit_movements (created_at)"))
        db.session.commit()

        # Ensure a default admin exists on first install only.
        # The password is set ONLY when the admin is created for the first time;
        # subsequent restarts preserve any password the operator may have changed.
        desired_username = 'VPNPro'
        desired_password = '123456'
        target_admin = Admin.query.filter_by(username=desired_username).first()

        if not target_admin:
            existing = Admin.query.first()
            if not existing:
                target_admin = Admin(username=desired_username)
                target_admin.set_password(desired_password)
                db.session.add(target_admin)
                db.session.commit()
                print('[*] Admin creado → usuario: VPNPro | clave: 123456')
            else:
                existing.username = desired_username
                db.session.commit()
                print('[*] Admin renombrado → usuario: VPNPro')

    if _is_background_worker_leader(app):
        _start_auto_sync_worker(app)
        _start_connection_limiter_worker(app)
        _start_disk_housekeeping_worker(app)
    else:
        app.logger.info(
            'Workers de background omitidos en este proceso (lider activo en otro worker de Gunicorn).'
        )

    return app


if __name__ == '__main__':
    application = create_app()
    application.run(host='0.0.0.0', port=application.config.get('WEB_PANEL_PORT', 80), debug=False)
