from __future__ import annotations

import json
import math
import os
import re
import secrets
import string
import time
import unicodedata
from datetime import datetime, timedelta
from threading import Lock

from flask import current_app, request, jsonify, flash, redirect, url_for

from models import VpnUser

_VPN_USERNAME_DASHES_RE = re.compile(r'[\u2010\u2011\u2012\u2013\u2014\u2212]')
VPN_USERNAME_PATTERN = re.compile(r'^[A-Z]+-[A-Z]+(?:-\d{2})?$')
DEMO_MAX_HOURS = 1
PACKAGE_OPTIONS = {
    'demo_1h': {'label': 'Demo 1 hora', 'hours': 1, 'months': 0, 'credits': 0},
    '1m': {'label': '1 Mes', 'days': 30, 'months': 1, 'credits': 1},
    '3m': {'label': '3 Meses', 'days': 90, 'months': 3, 'credits': 3},
    '6m': {'label': '6 Meses', 'days': 180, 'months': 6, 'credits': 6},
    '12m': {'label': '12 Meses', 'days': 360, 'months': 12, 'credits': 12},
}
_RUNTIME_CACHE: dict[str, tuple[float, object]] = {}
_RUNTIME_CACHE_LOCK = Lock()
_AUTO_TRIM_USER_COOLDOWN_SECONDS = 12
_AUTO_TRIM_CONFIRMATION_SECONDS = 8


def normalize_vpn_username(value: object) -> str:
    normalized = str(value or '').strip().upper()
    normalized = unicodedata.normalize('NFD', normalized)
    normalized = ''.join(ch for ch in normalized if unicodedata.category(ch) != 'Mn')
    normalized = _VPN_USERNAME_DASHES_RE.sub('-', normalized)
    normalized = re.sub(r'\s*-\s*', '-', normalized)
    normalized = re.sub(r'\s+', '', normalized)
    return normalized


def _load_panel_settings() -> dict[str, object]:
    settings_path = os.path.join(current_app.instance_path, 'panel_settings.json')
    if not os.path.isfile(settings_path):
        return {}

    with open(settings_path, 'r', encoding='utf-8') as fh:
        payload = json.load(fh)
    return payload if isinstance(payload, dict) else {}


def _get_panel_setting_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        settings = _load_panel_settings()
        value = int(settings.get(name, default) or default)
        return max(minimum, min(maximum, value))
    except Exception:
        return max(minimum, min(maximum, int(default)))


def parse_query_bool(value: object, default: bool = True) -> bool:
    if value is None:
        return bool(default)

    normalized = str(value).strip().lower()
    if normalized in {'1', 'true', 'yes', 'on', 'si'}:
        return True
    if normalized in {'0', 'false', 'no', 'off'}:
        return False
    return bool(default)


def get_online_check_interval_ms() -> int:
    fallback_ms = max(1000, int(current_app.config.get('ONLINE_CHECK_INTERVAL_MS', 10000) or 10000))
    fallback_seconds = max(1, min(300, int(fallback_ms / 1000)))
    seconds = _get_panel_setting_int('online_check_interval_seconds', fallback_seconds, 1, 300)
    return seconds * 1000


def get_limiter_interval_seconds() -> int:
    """Get interval (seconds) for applying connection limits via background worker."""
    fallback_seconds = max(2, int(current_app.config.get('AUTO_LIMITER_INTERVAL_SECONDS', 10) or 10))
    return _get_panel_setting_int('limiter_interval_seconds', fallback_seconds, 2, 60)


def serialize_user_for_ui(vpn_user: VpnUser) -> dict[str, object]:
    return {
        'id': int(vpn_user.id),
        'username': vpn_user.username,
        'password': vpn_user.password,
        'connection_limit': int(vpn_user.connection_limit or 1),
        'is_blocked': bool(vpn_user.is_blocked),
        'is_expired': bool(vpn_user.is_expired),
        'days_remaining': int(vpn_user.days_remaining),
        'expiry_date': vpn_user.expiry_date.strftime('%d/%m/%Y') if vpn_user.expiry_date else '',
        'expiry_datetime': vpn_user.expiry_date.strftime('%d/%m/%Y %H:%M') if vpn_user.expiry_date else '',
    }


def respond_user_action(
    endpoint: str,
    message: str,
    category: str,
    *,
    ok: bool,
    user: VpnUser | None = None,
    status_code: int = 200,
    user_serializer=None,
):
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        payload: dict[str, object] = {
            'ok': bool(ok),
            'message': message,
            'category': category,
        }
        if user is not None:
            serializer = user_serializer or serialize_user_for_ui
            payload['user'] = serializer(user)
        return jsonify(payload), status_code

    flash(message, category)
    return redirect(url_for(endpoint))


def compose_action_error(action_label: str, message: str) -> str:
    action = (action_label or '').strip()
    detail = (message or '').strip() or 'Error desconocido'
    if not action:
        return detail

    prefix = f'Error al {action}:'
    if detail.lower().startswith(prefix.lower()):
        return detail
    return f'{prefix} {detail}'


def compute_renewal_dates(expiry_date: datetime, renew_days: int) -> tuple[datetime, int]:
    """Return (new_expiry, days_from_now) for a renewal operation."""
    now = datetime.utcnow()
    renew_days = max(1, int(renew_days))
    if expiry_date and expiry_date > now:
        new_expiry = expiry_date + timedelta(days=renew_days)
    else:
        new_expiry = now + timedelta(days=renew_days)
    days_from_now = max(1, int(math.ceil((new_expiry - now).total_seconds() / 86400.0)))
    return new_expiry, days_from_now


def guard_server_storage_before_account_write(svc) -> tuple[bool, str]:
    """Abort account-changing actions if root disk usage is critical."""
    threshold = int(current_app.config.get('ROOT_DISK_CRITICAL_PERCENT', 98) or 98)
    ok, status, _ = svc.get_root_storage_status()
    if not ok:
        # Best-effort guard: if status cannot be read, continue normal flow.
        return True, ''

    used_blocks = int(status.get('blocks_used_percent', -1) or -1)
    used_inodes = int(status.get('inodes_used_percent', -1) or -1)
    if used_blocks < threshold and used_inodes < threshold:
        return True, ''

    attempted_cleanup = False
    if current_app.config.get('AUTO_DISK_HOUSEKEEPING_ON_GUARD', True):
        attempted_cleanup = True
        svc.run_disk_housekeeping(
            trigger_percent=max(50, threshold - 1),
            journal_max_mb=max(50, int(current_app.config.get('DISK_HOUSEKEEPING_JOURNAL_MAX_MB', 200) or 200)),
            tmp_max_age_days=max(1, int(current_app.config.get('DISK_HOUSEKEEPING_TMP_MAX_AGE_DAYS', 3) or 3)),
            aggressive=True,
        )
        ok_after, status_after, _ = svc.get_root_storage_status()
        if ok_after:
            used_after = int(status_after.get('blocks_used_percent', -1) or -1)
            inodes_after = int(status_after.get('inodes_used_percent', -1) or -1)
            if used_after >= 0 and used_after < threshold and inodes_after >= 0 and inodes_after < threshold:
                return True, ''
            status = status_after

    extra = ' Se intentó limpieza automática.' if attempted_cleanup else ''
    return False, (
        'Acción cancelada por almacenamiento crítico en el VPS. '
        f"Disco: {status.get('blocks', 'N/A')} | Inodos: {status.get('inodes', 'N/A')}."
        f'{extra} Libera espacio en la raíz del servidor y reintenta.'
    )


def cache_get(cache_key: str) -> object | None:
    now = time.monotonic()
    with _RUNTIME_CACHE_LOCK:
        entry = _RUNTIME_CACHE.get(cache_key)
        if not entry:
            return None
        expires_at, value = entry
        if expires_at <= now:
            _RUNTIME_CACHE.pop(cache_key, None)
            return None
        return value


def cache_set(cache_key: str, ttl_seconds: int, value: object) -> object:
    expires_at = time.monotonic() + max(1, int(ttl_seconds))
    with _RUNTIME_CACHE_LOCK:
        _RUNTIME_CACHE[cache_key] = (expires_at, value)
    return value


def get_online_snapshot_ttl_seconds() -> int:
    fallback_online_seconds = max(
        1,
        int(math.ceil(float(current_app.config.get('ONLINE_CHECK_INTERVAL_MS', 10000) or 10000) / 1000.0)),
    )
    fallback_seconds = max(3, fallback_online_seconds)
    return _get_panel_setting_int('online_snapshot_ttl_seconds', fallback_seconds, 3, 120)


def _normalize_online_counter_map(values: dict[str, object] | None) -> dict[str, int]:
    normalized: dict[str, int] = {}
    for username, amount in (values or {}).items():
        key = str(username or '').strip().upper()
        if not key:
            continue
        normalized[key] = max(0, int(amount or 0))
    return normalized


def get_online_snapshot_cache_key(server_id: int) -> str:
    return f'online-snapshot:{int(server_id)}'


def get_cached_online_snapshot(server_id: int) -> dict[str, object] | None:
    cached = cache_get(get_online_snapshot_cache_key(server_id))
    return cached if isinstance(cached, dict) else None


def cache_online_snapshot(
    server_id: int,
    online_map: dict[str, object] | None,
    *,
    device_map: dict[str, object] | None = None,
    connected_seconds_map: dict[str, object] | None = None,
) -> dict[str, object]:
    snapshot = {
        'online_map': _normalize_online_counter_map(online_map),
        'device_map': _normalize_online_counter_map(device_map),
        'connected_seconds_map': _normalize_online_counter_map(connected_seconds_map),
    }
    cache_set(get_online_snapshot_cache_key(server_id), get_online_snapshot_ttl_seconds(), snapshot)
    return snapshot


def generate_demo_username() -> str:
    suffix = ''.join(secrets.choice(string.ascii_uppercase) for _ in range(4))
    return f'DEMO-{suffix}'


def generate_demo_password(length: int = 10) -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def provision_demo_user(
    svc,
    existing_usernames: set[str],
    limit: int,
    attempts: int = 12,
) -> tuple[bool, str, str, str]:
    """Try to provision a demo user on VPS with bounded retries.

    Returns:
        (created, username, password, msg)
        - On success: created=True with generated username/password and service msg.
        - On hard failure: created=False and msg has the failure reason.
        - On exhaustion (all candidates busy): created=False and msg=''.
    """
    total_attempts = max(1, int(attempts or 1))
    safe_limit = max(1, int(limit or 1))

    for _ in range(total_attempts):
        username = generate_demo_username()
        username_key = (username or '').strip().upper()
        password = generate_demo_password(10)

        if username_key in existing_usernames:
            continue

        # Linux account expiry uses day granularity; enforce 1h by scheduled deletion.
        ok, msg = svc.create_user(username, password, 1, safe_limit)
        if ok:
            existing_usernames.add(username_key)
            return True, username, password, msg

        detail = (msg or '').strip()
        if 'ya existe en el servidor' in detail.lower():
            existing_usernames.add(username_key)
            continue

        return False, '', '', detail

    return False, '', '', ''


def resolve_package(package_code: str) -> dict:
    return PACKAGE_OPTIONS.get(package_code, PACKAGE_OPTIONS['1m'])


def pick_available_username(base_username: str) -> str:
    base = base_username.strip().upper()
    candidates = [base] + [f'{base}-{i:02d}' for i in range(100)]

    existing_usernames = load_active_usernames_upper()

    for candidate in candidates:
        if candidate not in existing_usernames:
            return candidate
    return ''


def load_active_usernames_upper() -> set[str]:
    rows = (
        VpnUser.query
        .with_entities(VpnUser.username)
        .filter_by(is_active=True)
        .all()
    )
    return {
        (username or '').strip().upper()
        for username, in rows
        if (username or '').strip()
    }


def build_user_create_success_message(
    service_msg: str,
    package_label: str,
    charged_credits: int,
    username: str,
    base_username: str,
) -> str:
    suffix = f" | Usuario asignado: {username}" if username != base_username else ''
    if int(charged_credits or 0) > 0:
        return (
            f"{service_msg} | Paquete: {package_label} | "
            f"Creditos cobrados: {int(charged_credits)}{suffix}"
        )
    return f"{service_msg} | Paquete: {package_label}{suffix}"


def apply_user_password_change(vpn_user: VpnUser, new_password: str, svc, db_session) -> tuple[bool, str]:
    ok, msg = svc.change_password(vpn_user.username, new_password)
    if ok:
        vpn_user.password = new_password
        db_session.commit()
    return ok, msg


def apply_user_limit_change(vpn_user: VpnUser, new_limit: int, svc, db_session) -> tuple[bool, str]:
    ok, msg = svc.change_limit(vpn_user.username, new_limit)
    if ok:
        vpn_user.connection_limit = new_limit
        db_session.commit()
    return ok, msg


def apply_user_block_state(vpn_user: VpnUser, block: bool, svc, db_session) -> tuple[bool, str]:
    if block:
        ok, msg = svc.block_user(vpn_user.username)
    else:
        ok, msg = svc.unblock_user(vpn_user.username)

    if ok:
        vpn_user.is_blocked = block
        db_session.commit()
    return ok, msg


def enforce_user_connection_limit(vpn_user: VpnUser, svc) -> tuple[bool, str]:
    """Keep only allowed active sessions for a user, without locking account."""
    username = (vpn_user.username or '').strip()
    limit = max(1, int(vpn_user.connection_limit or 1))

    ok, killed, msg = svc.trim_user_sessions(username, keep_sessions=limit)
    if not ok:
        return False, msg

    if killed > 0:
        return True, (
            f"Control aplicado a '{username}': "
            f"se mantuvieron {limit} conexión(es) y se cerraron {killed} excedente(s)."
        )

    return True, f"Control aplicado a '{username}': no había conexiones excedentes."


def calculate_observed_connection_count(
    sessions_count: int,
    devices_count: int,
    *,
    has_device_metric: bool,
) -> int:
    """Resolve effective online count balancing sessions/devices.

    Usa el mayor entre sesiones SSH activas y dispositivos distintos por IP.
    Esto garantiza que 2 sesiones desde el mismo NAT (mismo IP público)
    también se cuenten como 2 conexiones, aplicando el límite correctamente.
    """
    sessions = max(0, int(sessions_count or 0))
    devices = max(0, int(devices_count or 0))
    if has_device_metric and devices > 0:
        # Toma el máximo: si hay más sesiones que IPs distintas (mismo NAT),
        # las sesiones reales son el límite correcto a aplicar.
        observed = max(sessions, devices)
    else:
        observed = sessions
    return observed


def auto_block_users_exceeding_limit(
    user_rows: list[tuple[int, str, int, bool]],
    online_map: dict[str, int],
    svc,
    device_online_map: dict[str, int] | None = None,
) -> tuple[list[str], list[str]]:
    """Enforce connection limits for active users.

    Args:
        user_rows: (id, username, connection_limit, is_blocked) tuples.
        online_map: current online sessions keyed by uppercase username.
    Returns:
        (trimmed_usernames, errors)
    """
    if not user_rows:
        return [], []

    normalized_online = {
        (username or '').strip().upper(): int(sessions or 0)
        for username, sessions in (online_map or {}).items()
    }
    normalized_devices = {
        (username or '').strip().upper(): int(devices or 0)
        for username, devices in (device_online_map or {}).items()
    }

    to_enforce: list[tuple[str, int, bool]] = []
    try:
        trim_cooldown_seconds = max(
            1,
            int(current_app.config.get('AUTO_TRIM_USER_COOLDOWN_SECONDS', _AUTO_TRIM_USER_COOLDOWN_SECONDS) or _AUTO_TRIM_USER_COOLDOWN_SECONDS),
        )
    except Exception:
        trim_cooldown_seconds = _AUTO_TRIM_USER_COOLDOWN_SECONDS
    try:
        trim_confirmation_seconds = max(
            1,
            int(current_app.config.get('AUTO_TRIM_CONFIRMATION_SECONDS', _AUTO_TRIM_CONFIRMATION_SECONDS) or _AUTO_TRIM_CONFIRMATION_SECONDS),
        )
    except Exception:
        trim_confirmation_seconds = _AUTO_TRIM_CONFIRMATION_SECONDS
    first_strike_limit_one = bool(current_app.config.get('AUTO_TRIM_FIRST_STRIKE_LIMIT_ONE', True))

    for _user_id, username, connection_limit, is_blocked in user_rows:
        normalized = (username or '').strip().upper()
        sessions = max(0, int(normalized_online.get(normalized, 0)))
        devices = max(0, int(normalized_devices.get(normalized, 0)))
        limit = max(1, int(connection_limit or 1))
        observed = calculate_observed_connection_count(
            sessions,
            devices,
            has_device_metric=device_online_map is not None,
        )

        if observed > limit:
            if cache_get(f'auto-trim-cooldown:{normalized}') is not None:
                continue
            if first_strike_limit_one and limit <= 1:
                to_enforce.append((username, limit, bool(is_blocked)))
                continue
            confirmation_key = f'auto-trim-confirm:{normalized}'
            if cache_get(confirmation_key) is None:
                cache_set(confirmation_key, trim_confirmation_seconds, True)
                continue
            to_enforce.append((username, limit, bool(is_blocked)))

    if not to_enforce:
        return [], []

    trimmed_usernames: list[str] = []
    errors: list[str] = []

    ok, msg = svc.connect()
    if not ok:
        return [], [f'No se pudo abrir conexion SSH para control de sesiones: {msg}']

    try:
        for username, limit, was_blocked in to_enforce:
            if was_blocked:
                continue

            ok_trim, killed_sessions, trim_msg = svc.trim_user_sessions(username, keep_sessions=limit)
            if ok_trim:
                if killed_sessions > 0:
                    cache_set(
                        f'auto-trim-cooldown:{(username or "").strip().upper()}',
                        trim_cooldown_seconds,
                        True,
                    )
                    trimmed_usernames.append(username)
                continue

            errors.append(f"{username}: {trim_msg}")
    finally:
        svc.disconnect()

    return trimmed_usernames, errors
