from __future__ import annotations

from datetime import datetime, timedelta
from functools import wraps
import io
import os
import json
import re
import shutil
import sqlite3
import zipfile
import tempfile
import subprocess
import secrets
import time
import socket
import math
import platform
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from threading import Lock, Thread

COMMON_TIMEZONES: list[str] = [
    'America/Bogota', 'America/Lima', 'America/Guayaquil',
    'America/Panama', 'America/Costa_Rica', 'America/Managua',
    'America/Tegucigalpa', 'America/El_Salvador', 'America/Guatemala',
    'America/Mexico_City', 'America/Cancun', 'America/Monterrey',
    'America/Caracas', 'America/La_Paz', 'America/Asuncion',
    'America/Santiago', 'America/Argentina/Buenos_Aires',
    'America/Montevideo', 'America/Sao_Paulo', 'America/Manaus',
    'America/New_York', 'America/Chicago', 'America/Denver',
    'America/Los_Angeles', 'America/Toronto', 'America/Vancouver',
    'America/Havana', 'America/Santo_Domingo', 'America/Puerto_Rico',
    'Europe/Madrid', 'Europe/London', 'Europe/Paris', 'Europe/Berlin',
    'Europe/Rome', 'Europe/Lisbon', 'Europe/Amsterdam',
    'UTC',
    'Asia/Dubai', 'Asia/Tokyo', 'Asia/Singapore', 'Asia/Shanghai',
]


def _valid_timezone(tz: str) -> bool:
    try:
        ZoneInfo(tz)
        return True
    except (ZoneInfoNotFoundError, KeyError):
        return False
from sqlalchemy import func, or_
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import joinedload, load_only

from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify, send_file, current_app
from flask_login import login_required, current_user, logout_user

from models import db, Admin, Server, Reseller, VpnUser, CreditMovement
from services.ssh_service import SSHService
from routes.messages import (
    MSG_DEMO_NAME_EXHAUSTED,
    MSG_REQUIRED_FIELDS,
    MSG_USERNAME_FORMAT,
    msg_credits_insufficient,
    msg_demo_create_failed,
    msg_demo_schedule_warning,
)
from routes.shared_utils import (
    DEMO_MAX_HOURS,
    PACKAGE_OPTIONS,
    VPN_USERNAME_PATTERN,
    auto_block_users_exceeding_limit,
    apply_user_block_state,
    apply_user_limit_change,
    apply_user_password_change,
    build_user_create_success_message,
    cache_online_snapshot,
    cache_get,
    cache_set,
    compose_action_error,
    calculate_observed_connection_count,
    compute_renewal_dates,
    enforce_user_connection_limit,
    guard_server_storage_before_account_write,
    generate_demo_password,
    get_cached_online_snapshot,
    get_online_check_interval_ms,
    load_active_usernames_upper,
    normalize_vpn_username,
    pick_available_username,
    parse_query_bool,
    provision_demo_user,
    respond_user_action,
    resolve_package,
    serialize_user_for_ui,
)

admin_bp = Blueprint('admin', __name__)
SYSTEM_ADMIN_RESELLER_NOTE = '__SYSTEM_ADMIN_OWNER__'

_SERVER_INFO_TTL_SECONDS = 25
_SERVER_DELETE_SYNC_BATCH_SIZE = 25
_DELETE_SYNC_STATUS_LOCK = Lock()
_DELETE_SYNC_STATUS: dict[str, dict[str, object]] = {}
_DELETE_SYNC_STATUS_MAX_ITEMS = 40
_USER_SYNC_STATUS_LOCK = Lock()
_USER_SYNC_STATUS: dict[str, dict[str, object]] = {}
_USER_SYNC_STATUS_MAX_ITEMS = 50
_BACKUP_MAX_AGE_DAYS = 30
_BACKUP_MAX_FILES = 20
_RESTORE_BAK_MAX_FILES = 4
_BACKUP_HOUSEKEEPING_INTERVAL_SECONDS = 600
_RESTORE_GUARD_SECONDS = 180
_SETTINGS_CACHE_KEY = 'panel-settings'
_SETTINGS_CACHE_TTL_SECONDS = 5
_DASHBOARD_SERVER_METRICS_TTL_SECONDS = max(30, _SERVER_INFO_TTL_SECONDS)
_SERVER_NAME_NUMBER_RE = re.compile(r'\d+')


def _server_logical_sort_key(server: Server) -> tuple[int, int, str, int]:
    """Natural sort by first number in server name, then by name/id."""
    raw_name = (server.name or '').strip()
    lowered = raw_name.lower()
    match = _SERVER_NAME_NUMBER_RE.search(lowered)
    if match:
        return 0, int(match.group(0)), lowered, int(server.id or 0)
    return 1, 0, lowered, int(server.id or 0)


def _serialize_user_for_ui(u: VpnUser) -> dict[str, object]:
    payload = serialize_user_for_ui(u)
    reseller_label = 'No disponible'
    if u.reseller:
        reseller_label = 'Admin' if u.reseller.note == SYSTEM_ADMIN_RESELLER_NOTE else (u.reseller.username or 'No disponible')
    payload.update({
        'server_id': int(u.server_id or 0),
        'server_name': u.server.name if u.server else 'No disponible',
        'reseller_label': reseller_label,
    })
    return payload


def _parse_requested_user_ids() -> set[int] | None:
    requested_ids: set[int] = set()
    for raw_value in request.args.getlist('user_ids'):
        for chunk in str(raw_value or '').split(','):
            value = chunk.strip()
            if not value or not value.isdigit():
                continue
            requested_ids.add(int(value))
            if len(requested_ids) >= 250:
                return requested_ids
    return requested_ids or None


def _parse_requested_server_id() -> int | None:
    raw_value = str(request.args.get('server_id', '') or '').strip()
    if not raw_value.isdigit():
        return None
    server_id = int(raw_value)
    return server_id if server_id > 0 else None


def _respond_user_action(
    endpoint: str,
    message: str,
    category: str,
    *,
    ok: bool,
    user: VpnUser | None = None,
    status_code: int = 200,
):
    return respond_user_action(
        endpoint,
        message,
        category,
        ok=ok,
        user=user,
        status_code=status_code,
        user_serializer=_serialize_user_for_ui,
    )


def _respond_admin_users_action(
    message: str,
    category: str,
    *,
    ok: bool,
    user: VpnUser | None = None,
    status_code: int = 200,
):
    return _respond_user_action(
        'admin.users',
        message,
        category,
        ok=ok,
        user=user,
        status_code=status_code,
    )


def _respond_admin_user_not_found():
    return _respond_admin_users_action('Usuario no encontrado.', 'danger', ok=False, status_code=404)


def _create_delete_sync_status(
    source_server_name: str,
    target_server_name: str,
    total_users: int,
) -> str:
    sync_id = f"{int(time.time())}-{secrets.token_hex(3)}"
    item: dict[str, object] = {
        'id': sync_id,
        'source_server': source_server_name,
        'target_server': target_server_name,
        'status': 'queued',
        'total_users': int(total_users),
        'processed_users': 0,
        'created': 0,
        'already_existed': 0,
        'failed': 0,
        'message': 'Sincronización en cola.',
        'started_at': datetime.utcnow().isoformat(),
        'updated_at': datetime.utcnow().isoformat(),
    }
    with _DELETE_SYNC_STATUS_LOCK:
        _DELETE_SYNC_STATUS[sync_id] = item
        if len(_DELETE_SYNC_STATUS) > _DELETE_SYNC_STATUS_MAX_ITEMS:
            oldest = sorted(
                _DELETE_SYNC_STATUS.items(),
                key=lambda kv: str((kv[1] or {}).get('started_at', '')),
            )
            overflow = max(0, len(_DELETE_SYNC_STATUS) - _DELETE_SYNC_STATUS_MAX_ITEMS)
            for key, _ in oldest[:overflow]:
                _DELETE_SYNC_STATUS.pop(key, None)
    return sync_id


def _update_delete_sync_status(sync_id: str, **fields: object) -> None:
    with _DELETE_SYNC_STATUS_LOCK:
        item = _DELETE_SYNC_STATUS.get(sync_id)
        if not item:
            return
        for k, v in fields.items():
            item[k] = v
        item['updated_at'] = datetime.utcnow().isoformat()


def _list_delete_sync_status() -> list[dict[str, object]]:
    with _DELETE_SYNC_STATUS_LOCK:
        items = [dict(v) for v in _DELETE_SYNC_STATUS.values()]
    items.sort(key=lambda x: str(x.get('started_at', '')), reverse=True)
    return items[:20]


def _create_user_sync_status(
    server_id: int,
    server_name: str,
    total_users: int,
    sync_type: str = 'single',
) -> str:
    """Create a new user sync status record (single server or all servers)."""
    sync_id = f"{int(time.time())}-{secrets.token_hex(3)}"
    item: dict[str, object] = {
        'id': sync_id,
        'server_id': server_id,
        'server_name': server_name,
        'sync_type': sync_type,  # 'single' or 'all'
        'status': 'queued',
        'total_users': int(total_users),
        'processed_users': 0,
        'pushed': 0,
        'created': 0,
        'updated': 0,
        'deleted': 0,
        'failed': 0,
        'message': 'Sincronización en cola.',
        'started_at': datetime.utcnow().isoformat(),
        'updated_at': datetime.utcnow().isoformat(),
    }
    with _USER_SYNC_STATUS_LOCK:
        _USER_SYNC_STATUS[sync_id] = item
        if len(_USER_SYNC_STATUS) > _USER_SYNC_STATUS_MAX_ITEMS:
            oldest = sorted(
                _USER_SYNC_STATUS.items(),
                key=lambda kv: str((kv[1] or {}).get('started_at', '')),
            )
            overflow = max(0, len(_USER_SYNC_STATUS) - _USER_SYNC_STATUS_MAX_ITEMS)
            for key, _ in oldest[:overflow]:
                _USER_SYNC_STATUS.pop(key, None)
    return sync_id


def _update_user_sync_status(sync_id: str, **fields: object) -> None:
    """Update user sync status fields."""
    with _USER_SYNC_STATUS_LOCK:
        item = _USER_SYNC_STATUS.get(sync_id)
        if not item:
            return
        for k, v in fields.items():
            item[k] = v
        item['updated_at'] = datetime.utcnow().isoformat()


def _list_user_sync_status() -> list[dict[str, object]]:
    """Get recent user sync status items (sorted by started_at desc)."""
    with _USER_SYNC_STATUS_LOCK:
        items = [dict(v) for v in _USER_SYNC_STATUS.values()]
    items.sort(key=lambda x: str(x.get('started_at', '')), reverse=True)
    return items[:20]


_DISK_PCT_RE = re.compile(r'\((\d+)%\)')


def _parse_disk_pct(disk_str: str) -> int | None:
    """Extract integer percentage from a disk string like '34G / 72G (47%)'. Returns None on failure."""
    m = _DISK_PCT_RE.search(disk_str or '')
    return int(m.group(1)) if m else None


def _build_server_metrics_entry(ok: bool, info: dict[str, str]) -> dict[str, str | bool | int | None]:
    disk_str = info.get('disk', 'N/A') if ok else 'N/A'
    return {
        'ok': ok,
        'processor': info.get('processor', 'No disponible') if ok else 'No disponible',
        'cpu': info.get('cpu', 'N/A') if ok else 'N/A',
        'ram': info.get('ram', 'N/A') if ok else 'N/A',
        'disk': disk_str,
        'disk_pct': _parse_disk_pct(disk_str),
        'uptime': info.get('uptime', 'N/A') if ok else 'N/A',
        'online': info.get('online', '0') if ok else '0',
    }


def _cached_server_info(server: Server, *, allow_refresh: bool = True) -> tuple[bool, dict[str, str], str]:
    cache_key = f'server-info:{server.id}'
    cached = cache_get(cache_key)
    if cached is not None:
        return cached  # type: ignore[return-value]

    if not allow_refresh:
        return False, {}, 'cache-miss'

    svc = SSHService(server)
    result = svc.get_server_info()
    return cache_set(cache_key, _SERVER_INFO_TTL_SECONDS, result)  # type: ignore[return-value]


def _cached_dashboard_server_metrics_payload(
    servers: list[Server],
) -> dict[str, dict[str, str | bool | int | None]]:
    server_ids = ','.join(str(int(server.id)) for server in servers)
    cache_key = f'dashboard-server-metrics:{server_ids or "none"}'
    cached = cache_get(cache_key)
    if isinstance(cached, dict):
        return cached  # type: ignore[return-value]

    metrics: dict[str, dict[str, str | bool | int | None]] = {}
    for server in servers:
        ok, info, _ = _cached_server_info(server, allow_refresh=True)
        metrics[str(server.id)] = _build_server_metrics_entry(ok, info)

    cache_set(cache_key, _DASHBOARD_SERVER_METRICS_TTL_SECONDS, metrics)
    return metrics


def _read_cpu_times() -> tuple[int, int] | None:
    """Return (idle, total) cpu jiffies from /proc/stat."""
    try:
        with open('/proc/stat', 'r', encoding='utf-8') as fh:
            first = fh.readline().strip().split()
        if not first or first[0] != 'cpu' or len(first) < 5:
            return None
        nums = [int(v) for v in first[1:] if v.isdigit()]
        if len(nums) < 5:
            return None
        idle = nums[3] + nums[4]  # idle + iowait
        total = sum(nums)
        return idle, total
    except Exception:
        return None


def _local_cpu_usage() -> str:
    """Approximate local CPU usage percentage for panel host."""
    p1 = _read_cpu_times()
    if not p1:
        return 'N/A'
    time.sleep(0.18)
    p2 = _read_cpu_times()
    if not p2:
        return 'N/A'

    idle_delta = p2[0] - p1[0]
    total_delta = p2[1] - p1[1]
    if total_delta <= 0:
        return 'N/A'

    used_pct = max(0.0, min(100.0, (1.0 - (idle_delta / total_delta)) * 100.0))
    return f'{used_pct:.1f}%'


def _local_ram_usage() -> str:
    """Return local RAM usage in MB and percentage from /proc/meminfo."""
    try:
        mem_total_kb = None
        mem_avail_kb = None
        with open('/proc/meminfo', 'r', encoding='utf-8') as fh:
            for line in fh:
                if line.startswith('MemTotal:'):
                    mem_total_kb = int(line.split()[1])
                elif line.startswith('MemAvailable:'):
                    mem_avail_kb = int(line.split()[1])
                if mem_total_kb is not None and mem_avail_kb is not None:
                    break

        if not mem_total_kb or mem_avail_kb is None:
            return 'N/A'

        used_kb = max(0, mem_total_kb - mem_avail_kb)
        used_mb = used_kb / 1024.0
        total_mb = mem_total_kb / 1024.0
        pct = (used_kb / mem_total_kb) * 100.0 if mem_total_kb > 0 else 0.0
        return f'{used_mb:.0f}/{total_mb:.0f} MB ({pct:.0f}%)'
    except Exception:
        return 'N/A'


def _cached_local_panel_metrics() -> tuple[str, str]:
    cached = cache_get('local-panel-metrics')
    if isinstance(cached, tuple) and len(cached) == 2:
        return str(cached[0]), str(cached[1])

    cpu = _local_cpu_usage()
    ram = _local_ram_usage()
    cache_set('local-panel-metrics', 10, (cpu, ram))
    return cpu, ram


def _local_processor_type() -> str:
    """Return processor model/type for panel host."""
    try:
        with open('/proc/cpuinfo', 'r', encoding='utf-8') as fh:
            for line in fh:
                if line.lower().startswith('model name') and ':' in line:
                    value = line.split(':', 1)[1].strip()
                    if value:
                        return value
    except Exception:
        pass

    try:
        with open('/proc/device-tree/model', 'r', encoding='utf-8') as fh:
            value = fh.read().strip().replace('\x00', '')
            if value:
                return value
    except Exception:
        pass

    fallback = (platform.processor() or platform.machine() or '').strip()
    return fallback or 'No disponible'


def _cached_local_processor_type() -> str:
    cached = cache_get('local-panel-processor-type')
    if isinstance(cached, str) and cached.strip():
        return cached

    processor_type = _local_processor_type()
    cache_set('local-panel-processor-type', 10, processor_type)
    return processor_type


def _sqlite_db_path() -> str:
    uri = current_app.config.get('SQLALCHEMY_DATABASE_URI', '')
    prefix = 'sqlite:///'
    if not uri.startswith(prefix):
        raise ValueError('Solo se soporta backup/restauracion con SQLite.')
    return uri[len(prefix):]


def _sqlite_sidecar_paths(db_path: str) -> tuple[str, str]:
    return db_path + '-wal', db_path + '-shm'


def _remove_sqlite_sidecars(db_path: str) -> None:
    for sidecar_path in _sqlite_sidecar_paths(db_path):
        if not os.path.exists(sidecar_path):
            continue
        os.remove(sidecar_path)


def _find_zip_member(names: list[str], target_name: str) -> str | None:
    target_lower = target_name.lower()
    for name in names:
        if name.lower() == target_lower:
            return name
    for name in names:
        if name.lower().endswith('/' + target_lower) or name.lower().endswith('\\' + target_lower):
            return name
    return None


def _backups_dir() -> str:
    path = os.path.join(current_app.instance_path, 'backups')
    os.makedirs(path, exist_ok=True)
    return path


def _panel_tzinfo() -> ZoneInfo:
    tz = _get_panel_timezone()
    try:
        return ZoneInfo(tz)
    except (ZoneInfoNotFoundError, KeyError):
        return ZoneInfo('America/Bogota')


def _list_backups() -> list[dict]:
    path = _backups_dir()
    items = []
    for name in os.listdir(path):
        if not name.lower().endswith('.zip'):
            continue
        full_path = os.path.join(path, name)
        if not os.path.isfile(full_path):
            continue
        stat = os.stat(full_path)
        items.append({
            'name': name,
            'size_bytes': stat.st_size,
            'modified_at': datetime.fromtimestamp(stat.st_mtime, tz=ZoneInfo('UTC')).astimezone(_panel_tzinfo()),
        })
    items.sort(key=lambda x: x['modified_at'], reverse=True)
    return items


def _prune_backups(max_age_days: int = _BACKUP_MAX_AGE_DAYS, max_files: int = _BACKUP_MAX_FILES) -> tuple[int, int]:
    path = _backups_dir()
    removed_by_age = 0
    removed_by_count = 0
    now_ts = time.time()
    safe_max_age_days = max(1, int(max_age_days))
    safe_max_files = max(1, int(max_files))
    age_limit_seconds = safe_max_age_days * 86400

    candidates: list[tuple[str, float]] = []
    for name in os.listdir(path):
        if not name.lower().endswith('.zip'):
            continue
        full_path = os.path.join(path, name)
        if not os.path.isfile(full_path):
            continue
        try:
            stat = os.stat(full_path)
        except OSError:
            continue

        file_age_seconds = max(0.0, now_ts - float(stat.st_mtime))
        if file_age_seconds > age_limit_seconds:
            try:
                os.remove(full_path)
                removed_by_age += 1
                continue
            except OSError:
                current_app.logger.warning('No se pudo eliminar backup antiguo: %s', full_path)

        candidates.append((full_path, float(stat.st_mtime)))

    if len(candidates) > safe_max_files:
        candidates.sort(key=lambda item: item[1], reverse=True)
        overflow = candidates[safe_max_files:]
        for full_path, _ in overflow:
            try:
                os.remove(full_path)
                removed_by_count += 1
            except OSError:
                current_app.logger.warning('No se pudo eliminar backup excedente: %s', full_path)

    return removed_by_age, removed_by_count


def _prune_restore_artifacts(max_files: int = _RESTORE_BAK_MAX_FILES) -> int:
    """Keep a small number of latest *.pre-restore.bak artifacts in instance dir."""
    safe_max_files = max(1, int(max_files))
    root = current_app.instance_path
    candidates: list[tuple[str, float]] = []
    for name in os.listdir(root):
        if not name.endswith('.pre-restore.bak'):
            continue
        full_path = os.path.join(root, name)
        if not os.path.isfile(full_path):
            continue
        try:
            stat = os.stat(full_path)
        except OSError:
            continue
        candidates.append((full_path, float(stat.st_mtime)))

    if len(candidates) <= safe_max_files:
        return 0

    candidates.sort(key=lambda item: item[1], reverse=True)
    removed = 0
    for full_path, _ in candidates[safe_max_files:]:
        try:
            os.remove(full_path)
            removed += 1
        except OSError:
            current_app.logger.warning('No se pudo eliminar artefacto de restore: %s', full_path)
    return removed


def _safe_backup_file(filename: str) -> str | None:
    safe_name = os.path.basename(filename)
    if safe_name != filename or not safe_name.lower().endswith('.zip'):
        return None
    full_path = os.path.join(_backups_dir(), safe_name)
    if not os.path.isfile(full_path):
        return None
    return full_path


def _settings_file() -> str:
    os.makedirs(current_app.instance_path, exist_ok=True)
    return os.path.join(current_app.instance_path, 'panel_settings.json')


def _load_settings() -> dict:
    cached = cache_get(_SETTINGS_CACHE_KEY)
    if isinstance(cached, dict):
        return cached

    path = _settings_file()
    if not os.path.isfile(path):
        empty: dict = {}
        cache_set(_SETTINGS_CACHE_KEY, _SETTINGS_CACHE_TTL_SECONDS, empty)
        return empty
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
        parsed = data if isinstance(data, dict) else {}
        if 'primary_server_id' in parsed:
            parsed.pop('primary_server_id', None)
            try:
                with open(path, 'w', encoding='utf-8') as fh:
                    json.dump(parsed, fh, ensure_ascii=True, indent=2)
            except Exception:
                pass
        cache_set(_SETTINGS_CACHE_KEY, _SETTINGS_CACHE_TTL_SECONDS, parsed)
        return parsed
    except Exception:
        empty: dict = {}
        cache_set(_SETTINGS_CACHE_KEY, _SETTINGS_CACHE_TTL_SECONDS, empty)
        return empty


def _save_settings(settings: dict) -> None:
    path = _settings_file()
    with open(path, 'w', encoding='utf-8') as fh:
        json.dump(settings, fh, ensure_ascii=True, indent=2)
    cache_set(_SETTINGS_CACHE_KEY, _SETTINGS_CACHE_TTL_SECONDS, settings)


def _run_backup_housekeeping_if_due() -> None:
    cache_key = 'dashboard-backup-housekeeping'
    if cache_get(cache_key) is not None:
        return
    _prune_backups()
    _prune_restore_artifacts()
    cache_set(cache_key, _BACKUP_HOUSEKEEPING_INTERVAL_SECONDS, True)


def _get_panel_timezone() -> str:
    value = _load_settings().get('panel_timezone', 'America/Bogota')
    return value if isinstance(value, str) and _valid_timezone(value) else 'America/Bogota'


def _set_panel_timezone(tz: str) -> None:
    settings = _load_settings()
    settings['panel_timezone'] = tz
    _save_settings(settings)


def _get_online_check_interval_seconds() -> int:
    fallback = max(1, min(300, int((current_app.config.get('ONLINE_CHECK_INTERVAL_MS', 10000) or 10000) / 1000)))
    value = _load_settings().get('online_check_interval_seconds', fallback)
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = fallback
    return max(1, min(300, parsed))


def _set_online_check_interval_seconds(seconds: int) -> None:
    settings = _load_settings()
    settings['online_check_interval_seconds'] = max(1, min(300, int(seconds)))
    _save_settings(settings)


def _get_limiter_interval_seconds() -> int:
    fallback = max(2, min(60, int(current_app.config.get('AUTO_LIMITER_INTERVAL_SECONDS', 10) or 10)))
    value = _load_settings().get('limiter_interval_seconds', fallback)
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = fallback
    return max(2, min(60, parsed))


def _set_limiter_interval_seconds(seconds: int) -> None:
    settings = _load_settings()
    settings['limiter_interval_seconds'] = max(2, min(60, int(seconds)))
    _save_settings(settings)


def _get_first_connect_opened_ids() -> set[int]:
    value = _load_settings().get('first_connect_opened_server_ids', [])
    if not isinstance(value, list):
        return set()
    parsed: set[int] = set()
    for item in value:
        if isinstance(item, int):
            parsed.add(item)
    return parsed


def _mark_first_connect_opened(server_id: int) -> None:
    ids = _get_first_connect_opened_ids()
    ids.add(server_id)
    settings = _load_settings()
    settings['first_connect_opened_server_ids'] = sorted(ids)
    _save_settings(settings)


def _open_initial_ports_once(server: Server, svc: SSHService) -> tuple[list[str], list[str]]:
    tcp_ports = current_app.config.get('AUTO_OPEN_TCP_PORTS', []) or []
    udp_ports = current_app.config.get('AUTO_OPEN_UDP_PORTS', []) or []

    target_protocols: dict[int, list[str]] = {}
    for p in tcp_ports:
        target_protocols.setdefault(int(p), []).append('tcp')
    for p in udp_ports:
        target_protocols.setdefault(int(p), []).append('udp')

    opened: list[str] = []
    failed: list[str] = []

    for p, protocols in sorted(target_protocols.items()):
        okp, msgp = svc.open_port_rules(p, protocols)
        if okp:
            opened.append(f"{p}/{'/'.join(protocols)}")
        else:
            failed.append(f"{p}/{'/'.join(protocols)} ({msgp})")

    if not failed:
        _mark_first_connect_opened(server.id)

    return opened, failed


def _can_charge_credits(owner: Reseller, credits_needed: int) -> tuple[bool, str]:
    if credits_needed <= 0:
        return True, ''
    if owner.note == SYSTEM_ADMIN_RESELLER_NOTE:
        return True, ''
    if (owner.panel_credits or 0) < credits_needed:
        return False, msg_credits_insufficient(credits_needed, owner.panel_credits or 0, third_person=True)
    return True, ''


def _log_credit_movement(reseller: Reseller, delta: int, reason: str) -> None:
    db.session.add(
        CreditMovement(
            reseller_id=reseller.id,
            delta=delta,
            balance_after=reseller.panel_credits or 0,
            reason=reason,
        )
    )


def _get_or_create_system_reseller(server_id: int) -> Reseller:
    # Friendly, stable naming for system owner records used by sync.
    system_username = f"Admin-{server_id}"

    def _pick_available_system_username(preferred: str, exclude_id: int | None = None) -> str:
        candidate = preferred
        suffix = 1
        while True:
            q = Reseller.query.filter_by(username=candidate)
            if exclude_id is not None:
                q = q.filter(Reseller.id != exclude_id)
            if not q.first():
                return candidate
            candidate = f"Admin-{server_id}-SYS{suffix}"
            suffix += 1

    # 1) Preferred lookup by server + system note.
    existing = Reseller.query.filter_by(
        server_id=server_id,
        note=SYSTEM_ADMIN_RESELLER_NOTE,
    ).first()
    if existing:
        if existing.username != system_username:
            existing.username = _pick_available_system_username(system_username, exclude_id=existing.id)
            db.session.flush()
        return existing

    # 2) Legacy fallback: old generated username pattern.
    legacy_username = f"__ADMIN_OWNER_{server_id}__"
    legacy = Reseller.query.filter_by(username=legacy_username).first()
    if legacy:
        legacy.username = _pick_available_system_username(system_username, exclude_id=legacy.id)
        legacy.note = SYSTEM_ADMIN_RESELLER_NOTE
        legacy.server_id = server_id
        if legacy.is_active:
            legacy.is_active = False
        db.session.flush()
        return legacy

    r = Reseller(
        username=_pick_available_system_username(system_username),
        email='system@local',
        server_id=server_id,
        max_connections=9999,
        is_active=False,
        note=SYSTEM_ADMIN_RESELLER_NOTE,
    )
    r.set_password(f'system-{server_id}-{datetime.utcnow().timestamp()}')
    db.session.add(r)
    db.session.flush()
    return r


def _pick_server_transfer_target(source_server_id: int) -> Server | None:
    return (
        Server.query
        .filter(Server.id != source_server_id, Server.is_active.is_(True))
        .order_by(Server.id.asc())
        .first()
    )


def _build_vpn_transfer_payload(user: VpnUser) -> dict[str, object]:
    password = (user.password or '').strip() or generate_demo_password(12)
    if user.is_active and password != (user.password or '').strip():
        user.password = password

    return {
        'username': user.username,
        'password': password,
        'expiry_date': user.expiry_date,
        'connection_limit': max(1, int(user.connection_limit or 1)),
        'is_active': bool(user.is_active),
        'is_blocked': bool(user.is_blocked),
    }


def _migrate_vpn_user_payload_to_server(
    target_svc: SSHService,
    payload: dict[str, object],
) -> tuple[bool, str, str]:
    if not bool(payload.get('is_active')):
        return True, 'inactive', 'Usuario inactivo omitido en sincronización remota.'

    username = str(payload.get('username') or '').strip()
    password = str(payload.get('password') or '').strip() or generate_demo_password(12)
    expiry_date = payload.get('expiry_date')
    connection_limit = max(1, int(payload.get('connection_limit') or 1))
    is_blocked = bool(payload.get('is_blocked'))

    if not username or not isinstance(expiry_date, datetime):
        return False, 'failed', 'Payload de migración inválido.'

    now = datetime.utcnow()
    remaining_seconds = (expiry_date - now).total_seconds()
    create_days = max(1, int(math.ceil(max(remaining_seconds, 3600) / 86400.0)))

    ok, msg = target_svc.create_user(username, password, create_days, connection_limit)
    already_exists = not ok and 'ya existe en el servidor' in msg.lower()
    if not ok and not already_exists:
        return False, 'failed', msg

    if already_exists:
        ok, msg = target_svc.set_expiry_date(username, expiry_date)
        if not ok:
            return False, 'failed', f'No se pudo ajustar expiración: {msg}'
        if is_blocked:
            ok, msg = target_svc.block_user(username)
            if not ok:
                return False, 'failed', f'No se pudo restaurar estado bloqueado: {msg}'
        return True, 'already_existed', f"Usuario '{username}' ya existía en servidor destino."

    ok, msg = target_svc.set_expiry_date(username, expiry_date)
    if not ok:
        target_svc.delete_user(username)
        return False, 'failed', f'No se pudo ajustar expiración: {msg}'

    if remaining_seconds > 0 and remaining_seconds < 86400:
        hours = max(1, int(math.ceil(remaining_seconds / 3600.0)))
        sched_ok, sched_msg = target_svc.schedule_demo_lock(username, hours)
        if not sched_ok:
            target_svc.delete_user(username)
            return False, 'failed', f'No se pudo programar expiración corta: {sched_msg}'

    if is_blocked:
        ok, msg = target_svc.block_user(username)
        if not ok:
            target_svc.delete_user(username)
            return False, 'failed', f'No se pudo restaurar estado bloqueado: {msg}'

    return True, 'created', 'Usuario migrado al servidor destino.'


def _transfer_server_records_db_only(
    source_server: Server,
    target_server: Server,
) -> tuple[bool, dict[str, int], str, list[dict[str, object]]]:
    stats = {
        'resellers': 0,
        'users': 0,
        'admin_users': 0,
        'active_sync_queued': 0,
        'inactive_moved': 0,
    }

    source_users = (
        VpnUser.query
        .filter_by(server_id=source_server.id)
        .order_by(VpnUser.id.asc())
        .all()
    )
    remote_sync_payloads: list[dict[str, object]] = []

    for user in source_users:
        if not user.is_active:
            stats['inactive_moved'] += 1
        else:
            remote_sync_payloads.append(_build_vpn_transfer_payload(user))
            stats['active_sync_queued'] += 1

    target_admin_owner = _get_or_create_system_reseller(target_server.id)
    source_admin_owner = Reseller.query.filter_by(
        server_id=source_server.id,
        note=SYSTEM_ADMIN_RESELLER_NOTE,
    ).first()
    source_admin_owner_id = source_admin_owner.id if source_admin_owner else None

    normal_resellers = (
        Reseller.query
        .filter(Reseller.server_id == source_server.id, Reseller.note != SYSTEM_ADMIN_RESELLER_NOTE)
        .all()
    )
    for reseller in normal_resellers:
        reseller.server_id = target_server.id
        stats['resellers'] += 1

    for user in source_users:
        user.server_id = target_server.id
        stats['users'] += 1

    if source_admin_owner_id:
        admin_owned_users = VpnUser.query.filter_by(reseller_id=source_admin_owner_id).all()
        for user in admin_owned_users:
            # Reasignar por relación mantiene consistente el estado ORM y evita UPDATE a NULL.
            user.reseller = target_admin_owner
            stats['admin_users'] += 1

        CreditMovement.query.filter_by(reseller_id=source_admin_owner_id).delete(synchronize_session=False)
        # Delete through ORM instance to avoid stale rowcount mismatches on loaded entities.
        db.session.delete(source_admin_owner)

    db.session.flush()
    return True, stats, '', remote_sync_payloads


def _background_sync_deleted_server_users(
    app,
    sync_id: str,
    source_server_name: str,
    target_server_id: int,
    target_server_name: str,
    user_payloads: list[dict[str, object]],
) -> None:
    with app.app_context():
        guard_until = float(app.extensions.get('restore_guard_until', 0.0) or 0.0)
        if guard_until > time.time():
            _update_delete_sync_status(
                sync_id,
                status='failed',
                message='Sincronización diferida cancelada por ventana de protección post-restore.',
            )
            db.session.remove()
            return

        if not user_payloads:
            _update_delete_sync_status(
                sync_id,
                status='completed',
                message='No había usuarios activos para sincronización remota.',
                processed_users=0,
            )
            app.logger.info(
                "Eliminación de servidor '%s': no había usuarios activos para sincronizar al servidor '%s'.",
                source_server_name,
                target_server_name,
            )
            db.session.remove()
            return

        target_server = db.session.get(Server, target_server_id)
        if not target_server:
            _update_delete_sync_status(
                sync_id,
                status='failed',
                message=f"No se encontró el servidor destino (id={target_server_id}).",
            )
            app.logger.error(
                "Eliminación de servidor '%s': no se encontró el servidor destino id=%s para sincronización en segundo plano.",
                source_server_name,
                target_server_id,
            )
            db.session.remove()
            return

        svc = SSHService(target_server)
        ok, msg = svc.connect()
        if not ok:
            _update_delete_sync_status(
                sync_id,
                status='failed',
                message=f"No se pudo conectar al servidor destino: {msg}",
            )
            app.logger.error(
                "Eliminación de servidor '%s': no se pudo conectar al servidor destino '%s' para sincronización en segundo plano: %s",
                source_server_name,
                target_server_name,
                msg,
            )
            db.session.remove()
            return

        created = 0
        already_existed = 0
        failed = 0
        failures: list[str] = []
        total_batches = max(1, int(math.ceil(len(user_payloads) / _SERVER_DELETE_SYNC_BATCH_SIZE)))
        _update_delete_sync_status(
            sync_id,
            status='running',
            message='Sincronización remota en progreso.',
            processed_users=0,
            created=0,
            already_existed=0,
            failed=0,
            total_batches=total_batches,
            current_batch=0,
        )

        try:
            for batch_index, start in enumerate(range(0, len(user_payloads), _SERVER_DELETE_SYNC_BATCH_SIZE), start=1):
                batch = user_payloads[start:start + _SERVER_DELETE_SYNC_BATCH_SIZE]
                for payload in batch:
                    ok_user, status, detail = _migrate_vpn_user_payload_to_server(svc, payload)
                    if ok_user and status == 'created':
                        created += 1
                    elif ok_user and status == 'already_existed':
                        already_existed += 1
                    elif not ok_user:
                        failed += 1
                        failures.append(f"{payload.get('username', 'desconocido')}: {detail}")

                processed_users = min(len(user_payloads), start + len(batch))
                _update_delete_sync_status(
                    sync_id,
                    status='running',
                    message=f'Lote {batch_index}/{total_batches} procesado.',
                    processed_users=processed_users,
                    created=created,
                    already_existed=already_existed,
                    failed=failed,
                    total_batches=total_batches,
                    current_batch=batch_index,
                )

                app.logger.info(
                    (
                        "Sincronización diferida tras eliminar servidor '%s': lote %s/%s procesado hacia '%s' "
                        "(creados=%s, existentes=%s, fallidos=%s)."
                    ),
                    source_server_name,
                    batch_index,
                    total_batches,
                    target_server_name,
                    created,
                    already_existed,
                    failed,
                )

            if failures:
                app.logger.warning(
                    "Sincronización diferida tras eliminar servidor '%s': %s fallo(s). Muestras: %s",
                    source_server_name,
                    failed,
                    ' | '.join(failures[:10]),
                )

            _update_delete_sync_status(
                sync_id,
                status='completed',
                message=(
                    f"Completado: {created} creado(s), {already_existed} ya existente(s), {failed} fallido(s)."
                ),
                processed_users=len(user_payloads),
                created=created,
                already_existed=already_existed,
                failed=failed,
            )

            app.logger.info(
                (
                    "Sincronización diferida completada tras eliminar servidor '%s' hacia '%s': "
                    "%s creado(s), %s ya existentes, %s fallido(s)."
                ),
                source_server_name,
                target_server_name,
                created,
                already_existed,
                failed,
            )
        finally:
            try:
                svc.disconnect()
            finally:
                db.session.remove()


def _start_server_delete_background_sync(
    source_server_name: str,
    target_server_id: int,
    target_server_name: str,
    user_payloads: list[dict[str, object]],
) -> str:
    app = current_app._get_current_object()
    sync_id = _create_delete_sync_status(
        source_server_name=source_server_name,
        target_server_name=target_server_name,
        total_users=len(user_payloads),
    )
    thread = Thread(
        target=_background_sync_deleted_server_users,
        args=(app, sync_id, source_server_name, target_server_id, target_server_name, user_payloads),
        name=f'vpnpro-delete-sync-{target_server_id}-{int(time.time())}',
        daemon=True,
    )
    thread.start()
    return sync_id


def _build_panel_sync_preview(server: Server, remote_users: list[dict[str, object]]) -> dict[str, object]:
    panel_users = (
        VpnUser.query
        .options(
            load_only(VpnUser.id, VpnUser.username, VpnUser.is_active, VpnUser.server_id, VpnUser.reseller_id),
            joinedload(VpnUser.reseller).load_only(Reseller.id, Reseller.server_id),
        )
        .join(Reseller, VpnUser.reseller_id == Reseller.id)
        .filter(or_(VpnUser.server_id == server.id, Reseller.server_id == server.id))
        .order_by(VpnUser.id.desc())
        .all()
    )

    primary_by_norm: dict[str, VpnUser] = {}
    duplicate_rows: list[VpnUser] = []
    for panel_user in panel_users:
        username_raw = (panel_user.username or '').strip()
        if not username_raw:
            continue
        username_norm = username_raw.upper()
        existing = primary_by_norm.get(username_norm)
        if existing is None:
            primary_by_norm[username_norm] = panel_user
            continue
        if (not existing.is_active) and panel_user.is_active:
            duplicate_rows.append(existing)
            primary_by_norm[username_norm] = panel_user
            continue
        duplicate_rows.append(panel_user)

    deduped_panel = sum(1 for duplicate in duplicate_rows if duplicate.is_active)
    active_panel_users = [u for u in primary_by_norm.values() if u.is_active]
    active_panel_norms = {(u.username or '').strip().upper() for u in active_panel_users if (u.username or '').strip()}

    remote_by_norm: dict[str, dict[str, object]] = {}
    for remote_data in remote_users:
        username_raw = str(remote_data.get('username') or '').strip()
        if not username_raw:
            continue
        remote_by_norm[username_raw.upper()] = remote_data

    to_create = 0
    to_update = 0
    for panel_user in active_panel_users:
        username = (panel_user.username or '').strip().upper()
        if not username:
            continue
        if username in remote_by_norm:
            to_update += 1
        else:
            to_create += 1

    to_delete = 0
    for remote_norm in remote_by_norm:
        if remote_norm not in active_panel_norms:
            to_delete += 1

    return {
        'panel_total': len(active_panel_users),
        'remote_total': len(remote_by_norm),
        'to_create': to_create,
        'to_update': to_update,
        'to_delete': to_delete,
        'deduped_panel': deduped_panel,
    }


def _background_sync_server_users(
    app,
    sync_id: str,
    server_id: int,
    server_name: str,
) -> None:
    """Background worker: sync users for a single server."""
    with app.app_context():
        server = db.session.get(Server, server_id)
        if not server:
            _update_user_sync_status(
                sync_id,
                status='failed',
                message=f'No se encontró servidor con id={server_id}.',
            )
            db.session.remove()
            return

        ok, stats, err = _sync_server_users_data(server)
        
        if not ok:
            _update_user_sync_status(
                sync_id,
                status='failed',
                message=f'Error de sincronización: {err}',
            )
        else:
            try:
                db.session.commit()
            except Exception as commit_err:
                app.logger.error(f"Error al confirmar cambios de sincronización en {server_name}: {commit_err}")
            
            _update_user_sync_status(
                sync_id,
                status='completed',
                message=f"Completado: {stats['pushed']} aplicado(s), {stats['created_remote']} creado(s), "
                        f"{stats['updated_remote']} actualizado(s), {stats['deleted_remote']} eliminado(s).",
                processed_users=stats.get('panel_total', 0),
                pushed=stats.get('pushed', 0),
                created=stats.get('created_remote', 0),
                updated=stats.get('updated_remote', 0),
                deleted=stats.get('deleted_remote', 0),
                failed=stats.get('failed_ops', 0),
            )

        db.session.remove()


def _background_sync_all_servers_users(
    app,
    sync_id: str,
) -> None:
    """Background worker: sync users for all active servers."""
    with app.app_context():
        servers = Server.query.filter_by(is_active=True).all()
        servers = sorted(servers, key=_server_logical_sort_key)
        
        if not servers:
            _update_user_sync_status(
                sync_id,
                status='completed',
                message='No hay servidores activos para sincronizar.',
                processed_users=0,
            )
            db.session.remove()
            return

        total_panel = 0
        total_pushed = 0
        total_created = 0
        total_updated = 0
        total_deleted = 0
        total_failed = 0
        failed_servers: list[str] = []

        for idx, server in enumerate(servers, start=1):
            _update_user_sync_status(
                sync_id,
                status='running',
                message=f'Procesando servidor {idx}/{len(servers)}: {server.name}',
            )

            ok, stats, err = _sync_server_users_data(server)
            if not ok:
                failed_servers.append(f"{server.name}: {err}")
                continue

            total_panel += stats['panel_total']
            total_pushed += stats['pushed']
            total_created += stats['created_remote']
            total_updated += stats['updated_remote']
            total_deleted += stats['deleted_remote']
            total_failed += stats.get('failed_ops', 0)

        try:
            db.session.commit()
        except Exception as commit_err:
            app.logger.error(f"Error al confirmar cambios de sincronización masiva: {commit_err}")

        success_count = len(servers) - len(failed_servers)
        message = (
            f"Completado {success_count}/{len(servers)} servidor(es). "
            f"{total_pushed} aplicado(s), {total_created} creado(s), {total_updated} actualizado(s), "
            f"{total_deleted} eliminado(s), {total_failed} fallido(s)."
        )
        if failed_servers:
            message += f" Errores: {' | '.join(failed_servers[:5])}"

        _update_user_sync_status(
            sync_id,
            status='completed',
            message=message,
            processed_users=total_panel,
            pushed=total_pushed,
            created=total_created,
            updated=total_updated,
            deleted=total_deleted,
            failed=total_failed,
        )

        db.session.remove()


def _start_user_sync_background(
    server_id: int,
    server_name: str,
    total_users: int,
    sync_type: str = 'single',
) -> str:
    """Start a background user sync thread and return sync_id for tracking."""
    app = current_app._get_current_object()
    sync_id = _create_user_sync_status(
        server_id=server_id,
        server_name=server_name,
        total_users=total_users,
        sync_type=sync_type,
    )
    
    if sync_type == 'all':
        thread_func = _background_sync_all_servers_users
        args = (app, sync_id)
        thread_name = f'vpnpro-user-sync-all-{int(time.time())}'
    else:
        thread_func = _background_sync_server_users
        args = (app, sync_id, server_id, server_name)
        thread_name = f'vpnpro-user-sync-{server_id}-{int(time.time())}'

    thread = Thread(
        target=thread_func,
        args=args,
        name=thread_name,
        daemon=True,
    )
    thread.start()
    return sync_id


def _sync_server_users_data(server: Server, delete_remote: bool = True) -> tuple[bool, dict[str, int], str]:
    svc = SSHService(server)
    ok, remote_users, err = svc.list_users_for_sync()
    if not ok:
        return False, {}, err

    panel_users = (
        VpnUser.query
        .options(
            load_only(
                VpnUser.id,
                VpnUser.username,
                VpnUser._password,
                VpnUser.connection_limit,
                VpnUser.expiry_date,
                VpnUser.is_active,
                VpnUser.is_blocked,
                VpnUser.server_id,
                VpnUser.reseller_id,
            ),
            joinedload(VpnUser.reseller).load_only(Reseller.id, Reseller.server_id),
        )
        .join(Reseller, VpnUser.reseller_id == Reseller.id)
        .filter(or_(VpnUser.server_id == server.id, Reseller.server_id == server.id))
        .order_by(VpnUser.id.desc())
        .all()
    )

    relinked_server_rows = 0
    for panel_user in panel_users:
        reseller = panel_user.reseller
        if not reseller:
            continue
        if int(panel_user.server_id or 0) == int(server.id):
            continue
        if int(reseller.server_id or 0) != int(server.id):
            continue
        panel_user.server_id = server.id
        relinked_server_rows += 1

    primary_by_norm: dict[str, VpnUser] = {}
    duplicate_rows: list[VpnUser] = []
    for panel_user in panel_users:
        username_raw = (panel_user.username or '').strip()
        if not username_raw:
            continue
        username_norm = username_raw.upper()
        existing = primary_by_norm.get(username_norm)
        if existing is None:
            primary_by_norm[username_norm] = panel_user
            continue

        # Keep the active row as canonical if duplicates exist.
        if (not existing.is_active) and panel_user.is_active:
            duplicate_rows.append(existing)
            primary_by_norm[username_norm] = panel_user
            continue

        duplicate_rows.append(panel_user)

    # Detect duplicates but do not auto-disable them.
    # Auto-deactivation here can make freshly restored/imported users disappear unexpectedly.
    deduped_panel = sum(1 for duplicate in duplicate_rows if duplicate.is_active)

    active_panel_users: list[VpnUser] = [u for u in primary_by_norm.values() if u.is_active]
    active_panel_norms = {(u.username or '').strip().upper() for u in active_panel_users if (u.username or '').strip()}

    remote_by_norm: dict[str, dict[str, object]] = {}
    for remote_data in remote_users:
        username_raw = (remote_data.get('username') or '').strip()
        if not username_raw:
            continue
        remote_by_norm[username_raw.upper()] = remote_data

    pushed = 0
    created_remote = 0
    updated_remote = 0
    deleted_remote = 0
    blocked_applied = 0
    unblocked_applied = 0
    errors: list[str] = []

    ok_conn, err_conn = svc.connect()
    if not ok_conn:
        return False, {}, err_conn

    try:
        now_utc = datetime.utcnow()
        for panel_user in active_panel_users:
            username = (panel_user.username or '').strip()
            if not username:
                continue

            expiry_dt = panel_user.expiry_date or (now_utc + timedelta(days=1))
            total_days = max(1, int(math.ceil((expiry_dt - now_utc).total_seconds() / 86400.0)))
            limit = max(1, int(panel_user.connection_limit or 1))
            password = (panel_user.password or '').strip()
            if not password:
                password = generate_demo_password(12)
                panel_user.password = password

            existed_remote = username.upper() in remote_by_norm
            ok_user, msg_user = svc.create_user(username, password, total_days, limit)
            if not ok_user:
                errors.append(f"{username}: {msg_user}")
                continue

            ok_expiry, msg_expiry = svc.set_expiry_date(username, expiry_dt)
            if not ok_expiry:
                errors.append(f"{username}: {msg_expiry}")
                continue

            if panel_user.is_blocked:
                ok_block, msg_block = svc.block_user(username)
                if not ok_block:
                    errors.append(f"{username}: {msg_block}")
                    continue
                blocked_applied += 1
            else:
                ok_unblock, msg_unblock = svc.unblock_user(username)
                if not ok_unblock:
                    errors.append(f"{username}: {msg_unblock}")
                    continue
                unblocked_applied += 1

            pushed += 1
            if existed_remote:
                updated_remote += 1
            else:
                created_remote += 1

        if delete_remote:
            for remote_norm, remote_data in remote_by_norm.items():
                if remote_norm in active_panel_norms:
                    continue
                remote_username = str(remote_data.get('username') or '').strip()
                if not remote_username:
                    continue
                ok_delete, msg_delete = svc.delete_user(remote_username)
                if not ok_delete:
                    errors.append(f"{remote_username}: {msg_delete}")
                    continue
                deleted_remote += 1
    finally:
        svc.disconnect()

    return True, {
        'panel_total': len(active_panel_users),
        'pushed': pushed,
        'created_remote': created_remote,
        'updated_remote': updated_remote,
        'deleted_remote': deleted_remote,
        'blocked_applied': blocked_applied,
        'unblocked_applied': unblocked_applied,
        'deduped_panel': deduped_panel,
        'relinked_server_rows': relinked_server_rows,
        'remote_total': len(remote_by_norm),
        'failed_ops': len(errors),
    }, ' | '.join(errors[:8]) if errors else ''


def _build_transfer_users_preview(source_server: Server, target_server: Server) -> dict[str, int]:
    source_resellers = (
        Reseller.query
        .options(load_only(Reseller.id, Reseller.server_id, Reseller.note))
        .filter(Reseller.server_id == source_server.id)
        .filter(or_(Reseller.note.is_(None), Reseller.note != SYSTEM_ADMIN_RESELLER_NOTE))
        .all()
    )

    source_users = (
        VpnUser.query
        .options(
            load_only(VpnUser.id, VpnUser.username, VpnUser.is_active, VpnUser.server_id, VpnUser.reseller_id),
            joinedload(VpnUser.reseller).load_only(Reseller.id, Reseller.note),
        )
        .filter(VpnUser.server_id == source_server.id)
        .all()
    )

    target_active_usernames = {
        (username or '').strip().upper()
        for (username,) in (
            db.session.query(VpnUser.username)
            .filter(VpnUser.server_id == target_server.id, VpnUser.is_active.is_(True))
            .all()
        )
        if (username or '').strip()
    }

    active_total = 0
    inactive_total = 0
    conflicts = 0
    reseller_ids: set[int] = set()
    reseller_ids_blocked_by_conflict: set[int] = set()

    for user in source_users:
        reseller = user.reseller
        if reseller and reseller.note != SYSTEM_ADMIN_RESELLER_NOTE:
            reseller_ids.add(int(reseller.id))

        username_norm = (user.username or '').strip().upper()
        if user.is_active:
            active_total += 1
            if username_norm and username_norm in target_active_usernames:
                conflicts += 1
                if reseller and reseller.note != SYSTEM_ADMIN_RESELLER_NOTE:
                    reseller_ids_blocked_by_conflict.add(int(reseller.id))
        else:
            inactive_total += 1

    return {
        'total_source': len(source_users),
        'active_total': active_total,
        'purge_inactive_estimate': inactive_total,
        'active_conflicts': conflicts,
        'active_transferable': max(0, active_total - conflicts),
        'resellers_to_move_estimate': max(0, len(source_resellers) - len(reseller_ids_blocked_by_conflict)),
    }


def _background_transfer_server_users(
    app,
    sync_id: str,
    source_server_id: int,
    target_server_id: int,
    user_ids: list[int],
) -> None:
    with app.app_context():
        guard_until = float(app.extensions.get('restore_guard_until', 0.0) or 0.0)
        if guard_until > time.time():
            _update_delete_sync_status(
                sync_id,
                status='failed',
                message='Transferencia diferida cancelada por ventana de protección post-restore.',
            )
            db.session.remove()
            return

        source_server = db.session.get(Server, source_server_id)
        target_server = db.session.get(Server, target_server_id)
        if not source_server or not target_server:
            _update_delete_sync_status(
                sync_id,
                status='failed',
                message='No se encontró servidor origen o destino para completar la transferencia.',
            )
            db.session.remove()
            return

        moved_active = 0
        purged_inactive = 0
        failed = 0
        skipped_conflicts = 0
        ownership_adjusted = 0
        resellers_moved = 0
        resellers_pending = 0
        deleted_source_remote = 0
        delete_source_remote_failed = 0
        errors: list[str] = []
        candidate_reseller_ids: set[int] = {
            int(rid)
            for (rid,) in (
                db.session.query(Reseller.id)
                .filter(Reseller.server_id == source_server.id)
                .filter(or_(Reseller.note.is_(None), Reseller.note != SYSTEM_ADMIN_RESELLER_NOTE))
                .all()
            )
        }

        total = len(user_ids)
        total_batches = max(1, int(math.ceil(total / _SERVER_DELETE_SYNC_BATCH_SIZE)))
        _update_delete_sync_status(
            sync_id,
            status='running',
            message='Transferencia de usuarios en progreso.',
            processed_users=0,
            created=0,
            already_existed=0,
            failed=0,
            total_batches=total_batches,
            current_batch=0,
        )

        target_svc = SSHService(target_server)
        source_svc = SSHService(source_server)

        ok_target, err_target = target_svc.connect()
        if not ok_target:
            _update_delete_sync_status(
                sync_id,
                status='failed',
                message=f"No se pudo conectar al VPS destino: {err_target}",
            )
            db.session.remove()
            return

        ok_source, err_source = source_svc.connect()
        if not ok_source:
            target_svc.disconnect()
            _update_delete_sync_status(
                sync_id,
                status='failed',
                message=f"No se pudo conectar al VPS origen: {err_source}",
            )
            db.session.remove()
            return

        target_admin_owner: Reseller | None = None

        def _commit_with_retry(max_attempts: int = 4) -> None:
            for attempt in range(1, max_attempts + 1):
                try:
                    db.session.commit()
                    return
                except OperationalError as ex:
                    db.session.rollback()
                    msg = str(ex).lower()
                    if 'database is locked' in msg and attempt < max_attempts:
                        time.sleep(0.2 * attempt)
                        continue
                    raise

        def ensure_target_admin_owner() -> Reseller:
            nonlocal target_admin_owner
            if target_admin_owner is None:
                target_admin_owner = _get_or_create_system_reseller(target_server.id)
            return target_admin_owner

        try:
            for batch_index, start in enumerate(range(0, total, _SERVER_DELETE_SYNC_BATCH_SIZE), start=1):
                batch_ids = user_ids[start:start + _SERVER_DELETE_SYNC_BATCH_SIZE]
                batch_users = (
                    VpnUser.query
                    .options(
                        load_only(
                            VpnUser.id,
                            VpnUser.username,
                            VpnUser._password,
                            VpnUser.connection_limit,
                            VpnUser.expiry_date,
                            VpnUser.is_active,
                            VpnUser.is_blocked,
                            VpnUser.server_id,
                            VpnUser.reseller_id,
                        ),
                        joinedload(VpnUser.reseller).load_only(Reseller.id, Reseller.username, Reseller.note, Reseller.server_id),
                    )
                    .filter(VpnUser.id.in_(batch_ids))
                    .all()
                )
                by_id = {u.id: u for u in batch_users}

                for uid in batch_ids:
                    with db.session.no_autoflush:
                        user = by_id.get(uid)
                        if not user:
                            failed += 1
                            errors.append(f'id={uid}: no encontrado')
                            continue

                        if int(user.server_id or 0) != int(source_server.id):
                            continue

                        username = (user.username or '').strip()
                        if not username:
                            failed += 1
                            errors.append(f'id={uid}: username vacío')
                            continue

                        conflict = (
                            VpnUser.query
                            .filter(VpnUser.id != user.id)
                            .filter(VpnUser.server_id == target_server.id)
                            .filter(VpnUser.is_active.is_(True))
                            .filter(func.upper(VpnUser.username) == username.upper())
                            .first()
                        )
                        if conflict:
                            skipped_conflicts += 1
                            continue

                        if not user.is_active:
                            # Eliminar inactivos/expirados: borrar del VPS origen y de la DB.
                            source_svc.delete_user(username)  # best-effort, ignorar error
                            db.session.delete(user)
                            purged_inactive += 1
                            continue

                        payload = _build_vpn_transfer_payload(user)
                        ok_move, _status, detail = _migrate_vpn_user_payload_to_server(target_svc, payload)
                        if not ok_move:
                            failed += 1
                            safe_detail = str(detail or '').replace('\n', ' ').replace('\r', ' ').strip()
                            errors.append(f"{username}: {safe_detail[:180]}")
                            continue

                        ok_delete_src, _msg_delete_src = source_svc.delete_user(username)
                        if not ok_delete_src:
                            delete_source_remote_failed += 1
                            errors.append(f"{username}: No se pudo eliminar del servidor origen: {_msg_delete_src}")
                            continue

                        deleted_source_remote += 1
                        moved_active += 1

                        user.server_id = target_server.id

                        if user.reseller and user.reseller.note == SYSTEM_ADMIN_RESELLER_NOTE:
                            owner = ensure_target_admin_owner()
                            if int(user.reseller_id or 0) != int(owner.id):
                                user.reseller_id = owner.id
                                ownership_adjusted += 1

                _commit_with_retry()

                processed_users = min(total, start + len(batch_ids))
                _update_delete_sync_status(
                    sync_id,
                    status='running',
                    message=(
                        f'Lote {batch_index}/{total_batches}: activos={moved_active}, '
                        f'inactivos_eliminados={purged_inactive}, conflictos={skipped_conflicts}, fallidos={failed}.'
                    ),
                    processed_users=processed_users,
                    created=moved_active,
                    already_existed=purged_inactive,
                    failed=failed,
                    total_batches=total_batches,
                    current_batch=batch_index,
                )

            if candidate_reseller_ids:
                remaining_source_rows = dict(
                    db.session.query(VpnUser.reseller_id, func.count(VpnUser.id))
                    .filter(VpnUser.reseller_id.in_(list(candidate_reseller_ids)))
                    .filter(VpnUser.server_id == source_server.id)
                    .group_by(VpnUser.reseller_id)
                    .all()
                )
                candidate_resellers = (
                    Reseller.query
                    .filter(Reseller.id.in_(list(candidate_reseller_ids)))
                    .all()
                )
                for reseller in candidate_resellers:
                    if remaining_source_rows.get(int(reseller.id), 0) > 0:
                        resellers_pending += 1
                        continue
                    if int(reseller.server_id or 0) != int(target_server.id):
                        reseller.server_id = target_server.id
                        resellers_moved += 1

                if resellers_moved > 0:
                    _commit_with_retry()

            message = (
                f"Transferencia completada: activos={moved_active}, inactivos_eliminados={purged_inactive}, "
                f"propietarios_ajustados={ownership_adjusted}, revendedores_movidos={resellers_moved}, "
                f"revendedores_pendientes={resellers_pending}, conflictos={skipped_conflicts}, "
                f"borrados_origen={deleted_source_remote}, no_borrados_origen={delete_source_remote_failed}, fallidos={failed}."
            )
            if errors:
                sample = ' | '.join(errors[:5])
                if len(errors) > 5:
                    sample = f"{sample} | ... y {len(errors) - 5} error(es) más"
                message = f"{message} Detalle: {sample[:700]}"

            _update_delete_sync_status(
                sync_id,
                status='completed',
                message=message,
                processed_users=total,
                created=moved_active,
                already_existed=purged_inactive,
                failed=failed,
                skipped_conflicts=skipped_conflicts,
                ownership_adjusted=ownership_adjusted,
                resellers_moved=resellers_moved,
                resellers_pending=resellers_pending,
                deleted_source_remote=deleted_source_remote,
                delete_source_remote_failed=delete_source_remote_failed,
            )
        except Exception as ex:
            db.session.rollback()
            current_app.logger.exception(
                'Error en transferencia diferida de usuarios origen=%s destino=%s',
                source_server_id,
                target_server_id,
            )
            _update_delete_sync_status(
                sync_id,
                status='failed',
                message=f'Error interno en transferencia diferida: {str(ex)[:220]}',
            )
        finally:
            try:
                source_svc.disconnect()
            finally:
                target_svc.disconnect()
                db.session.remove()


def _start_transfer_users_background_sync(
    source_server: Server,
    target_server: Server,
    user_ids: list[int],
) -> str:
    app = current_app._get_current_object()
    source_label = f"{source_server.name} [id={source_server.id}]"
    target_label = f"{target_server.name} [id={target_server.id}]"
    sync_id = _create_delete_sync_status(
        source_server_name=f"{source_label} (transfer)",
        target_server_name=target_label,
        total_users=len(user_ids),
    )
    thread = Thread(
        target=_background_transfer_server_users,
        args=(app, sync_id, source_server.id, target_server.id, user_ids),
        name=f'vpnpro-transfer-sync-{source_server.id}-{target_server.id}-{int(time.time())}',
        daemon=True,
    )
    thread.start()
    return sync_id


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not isinstance(current_user, Admin):
            flash('Acceso restringido a administradores.', 'danger')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return login_required(decorated)


# ──────────────────────────────────────────────────────────
# Dashboard
# ──────────────────────────────────────────────────────────

@admin_bp.route('/')
@admin_required
def dashboard():
    _run_backup_housekeeping_if_due()

    total_servers = Server.query.count()
    total_resellers = Reseller.query.filter(Reseller.note != SYSTEM_ADMIN_RESELLER_NOTE).count()
    total_vpn_users = VpnUser.query.filter_by(is_active=True).count()
    servers = (
        Server.query
        .options(load_only(Server.id, Server.name, Server.ip, Server.port, Server.is_active))
        .all()
    )
    servers = sorted(servers, key=_server_logical_sort_key)
    server_metrics: dict[int, dict[str, str | bool]] = {}
    server_user_counts_raw = (
        db.session.query(VpnUser.server_id, func.count(VpnUser.id))
        .filter(VpnUser.is_active.is_(True))
        .group_by(VpnUser.server_id)
        .all()
    )
    reseller_counts_raw = (
        db.session.query(Reseller.server_id, func.count(Reseller.id))
        .filter(Reseller.note != SYSTEM_ADMIN_RESELLER_NOTE)
        .group_by(Reseller.server_id)
        .all()
    )
    server_user_counts = {sid: int(total) for sid, total in server_user_counts_raw}
    reseller_counts = {sid: int(total) for sid, total in reseller_counts_raw}

    for sv in servers:
        ok, info, _ = _cached_server_info(sv, allow_refresh=False)
        server_metrics[sv.id] = _build_server_metrics_entry(ok, info)
    recent_users = (
        VpnUser.query
        .options(joinedload(VpnUser.reseller))
        .order_by(VpnUser.created_at.desc())
        .limit(2)
        .all()
    )
    local_panel_cpu, local_panel_ram = _cached_local_panel_metrics()
    local_panel_processor_type = _cached_local_processor_type()
    local_panel_host = socket.gethostname() or 'panel-web'
    try:
        panel_database_path = _sqlite_db_path()
    except ValueError:
        panel_database_path = current_app.config.get('SQLALCHEMY_DATABASE_URI', 'N/A')

    return render_template(
        'admin/dashboard.html',
        total_servers=total_servers,
        total_resellers=total_resellers,
        total_vpn_users=total_vpn_users,
        servers=servers,
        server_metrics=server_metrics,
        recent_users=recent_users,
        backup_files=_list_backups(),
        local_panel_cpu=local_panel_cpu,
        local_panel_ram=local_panel_ram,
        local_panel_processor_type=local_panel_processor_type,
        local_panel_host=local_panel_host,
        panel_data_dir=current_app.instance_path,
        panel_database_path=panel_database_path,
        panel_timezone=_get_panel_timezone(),
        server_user_counts=server_user_counts,
        reseller_counts=reseller_counts,
        online_check_interval_ms=get_online_check_interval_ms(),
    )


@admin_bp.route('/dashboard/server-metrics')
@admin_required
def dashboard_server_metrics():
    servers = (
        Server.query
        .options(load_only(Server.id, Server.name, Server.is_active))
        .order_by(Server.id.asc())
        .all()
    )

    metrics = _cached_dashboard_server_metrics_payload(servers)

    return jsonify({'ok': True, 'metrics': metrics})


@admin_bp.route('/account', methods=['POST'])
@admin_required
def update_account():
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')

    if not current_user.check_password(current_password):
        flash('La contraseña actual no es correcta.', 'danger')
        return redirect(url_for('admin.dashboard'))

    changed = False
    password_changed = False

    if new_password:
        if len(new_password) < 6:
            flash('La nueva contraseña debe tener al menos 6 caracteres.', 'danger')
            return redirect(url_for('admin.dashboard'))
        if new_password != confirm_password:
            flash('La confirmación de contraseña no coincide.', 'danger')
            return redirect(url_for('admin.dashboard'))
        current_user.set_password(new_password)
        password_changed = True
        changed = True

    if not changed:
        flash('No se detectaron cambios para guardar.', 'warning')
        return redirect(url_for('admin.dashboard'))

    db.session.commit()
    if password_changed:
        logout_user()
        flash('Contraseña actualizada. Inicia sesión nuevamente.', 'success')
        return redirect(url_for('auth.login'))

    flash('Credenciales de administrador actualizadas.', 'success')
    return redirect(url_for('admin.dashboard'))


# ──────────────────────────────────────────────────────────
# Servers
# ──────────────────────────────────────────────────────────

@admin_bp.route('/servers', methods=['GET', 'POST'])
@admin_required
def servers():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        ip = request.form.get('ip', '').strip()
        port = int(request.form.get('port', 22) or 22)
        ssh_user = request.form.get('ssh_user', 'root').strip() or 'root'
        ssh_password = request.form.get('ssh_password', '')
        description = request.form.get('description', '').strip()
        timezone = request.form.get('timezone', 'America/Bogota').strip() or 'America/Bogota'
        if not _valid_timezone(timezone):
            timezone = 'America/Bogota'

        if not name or not ip or not ssh_password:
            flash('Nombre, IP y contraseña SSH son obligatorios.', 'danger')
        else:
            # Verificar credenciales SSH antes de guardar el servidor
            _tmp = Server(name=name, ip=ip, port=port, ssh_user=ssh_user)
            _tmp.set_ssh_password(ssh_password)
            svc = SSHService(_tmp)
            ok, err_msg = svc.connect()
            svc.disconnect()
            if not ok:
                flash(f"No se pudo autenticar en el servidor: {err_msg}", 'danger')
            else:
                server = Server(
                    name=name, ip=ip, port=port,
                    ssh_user=ssh_user, description=description,
                    timezone=timezone,
                )
                server.set_ssh_password(ssh_password)
                db.session.add(server)
                db.session.commit()
                flash(f"Servidor '{name}' agregado.", 'success')
        return redirect(url_for('admin.servers'))

    all_servers = Server.query.all()
    all_servers = sorted(all_servers, key=_server_logical_sort_key)
    transfer_preview: dict[int, dict[str, str | int | None]] = {}
    reseller_counts_raw = (
        db.session.query(Reseller.server_id, func.count(Reseller.id))
        .filter(Reseller.note != SYSTEM_ADMIN_RESELLER_NOTE)
        .group_by(Reseller.server_id)
        .all()
    )
    user_counts_raw = (
        db.session.query(VpnUser.server_id, func.count(VpnUser.id))
        .filter(VpnUser.is_active.is_(True))
        .group_by(VpnUser.server_id)
        .all()
    )
    reseller_counts = {sid: int(total) for sid, total in reseller_counts_raw}
    user_counts = {sid: int(total) for sid, total in user_counts_raw}

    # Drift: usuarios activos cuyo server_id != reseller.server_id agrupados por VpnUser.server_id.
    drift_rows = (
        db.session.query(VpnUser.server_id, func.count(VpnUser.id))
        .join(Reseller, VpnUser.reseller_id == Reseller.id)
        .filter(VpnUser.is_active.is_(True))
        .filter(VpnUser.server_id != Reseller.server_id)
        .filter(or_(Reseller.note.is_(None), Reseller.note != SYSTEM_ADMIN_RESELLER_NOTE))
        .group_by(VpnUser.server_id)
        .all()
    )
    drift_by_server: dict[int, int] = {sid: int(cnt) for sid, cnt in drift_rows}
    total_drift = sum(drift_by_server.values())

    for sv in all_servers:
        target_server = _pick_server_transfer_target(sv.id)
        transfer_preview[sv.id] = {
            'target_name': target_server.name if target_server else None,
            'reseller_count': reseller_counts.get(sv.id, 0),
            'user_count': user_counts.get(sv.id, 0),
            'drift_users': drift_by_server.get(sv.id, 0),
        }

    return render_template(
        'admin/servers.html',
        servers=all_servers,
        transfer_preview=transfer_preview,
        total_drift=total_drift,
        common_timezones=COMMON_TIMEZONES,
        panel_timezone=_get_panel_timezone(),
        online_check_interval_seconds=_get_online_check_interval_seconds(),
        limiter_interval_seconds=_get_limiter_interval_seconds(),
    )


@admin_bp.route('/servers/<int:server_id>/edit', methods=['POST'])
@admin_required
def edit_server(server_id: int):
    server = db.session.get(Server, server_id)
    if not server:
        flash('Servidor no encontrado.', 'danger')
        return redirect(url_for('admin.servers'))

    name = request.form.get('name', '').strip()
    ip = request.form.get('ip', '').strip()
    try:
        port = int(request.form.get('port', 22) or 22)
    except ValueError:
        port = 22
    ssh_user = request.form.get('ssh_user', 'root').strip() or 'root'
    ssh_password = request.form.get('ssh_password', '').strip()
    description = request.form.get('description', '').strip()
    timezone = request.form.get('timezone', 'America/Bogota').strip() or 'America/Bogota'
    if not _valid_timezone(timezone):
        timezone = 'America/Bogota'

    if not name or not ip:
        flash('Nombre e IP son obligatorios.', 'danger')
        return redirect(url_for('admin.servers'))

    server.name = name
    server.ip = ip
    server.port = port
    server.ssh_user = ssh_user
    server.description = description
    server.timezone = timezone

    if ssh_password:
        server.set_ssh_password(ssh_password)

    db.session.commit()
    flash(f"Servidor '{name}' actualizado.", 'success')
    return redirect(url_for('admin.servers'))


@admin_bp.route('/servers/sync-preview-all', methods=['POST'])
@admin_required
def sync_preview_all_servers_users():
    servers = Server.query.filter_by(is_active=True).all()
    servers = sorted(servers, key=_server_logical_sort_key)
    if not servers:
        flash('No hay servidores activos para previsualizar.', 'warning')
        return redirect(url_for('admin.servers'))

    total_panel = 0
    total_remote = 0
    total_create = 0
    total_update = 0
    total_delete = 0
    total_deduped = 0
    details: list[str] = []
    errors: list[str] = []

    for server in servers:
        svc = SSHService(server)
        ok, remote_users, err = svc.list_users_for_sync()
        if not ok:
            errors.append(f'{server.name}: {err}')
            continue

        stats = _build_panel_sync_preview(server, remote_users)
        total_panel += int(stats['panel_total'])
        total_remote += int(stats['remote_total'])
        total_create += int(stats['to_create'])
        total_update += int(stats['to_update'])
        total_delete += int(stats['to_delete'])
        total_deduped += int(stats['deduped_panel'])
        details.append(
            (
                f"{server.name}: panel={stats['panel_total']}, VPS={stats['remote_total']}, "
                f"crear={stats['to_create']}, actualizar={stats['to_update']}, "
                f"eliminar={stats['to_delete']}, duplicados_panel={stats['deduped_panel']}"
            )
        )

    flash(
        (
            f'Previsualizacion panel -> VPS: panel={total_panel}, VPS={total_remote}, '
            f'crear={total_create}, actualizar={total_update}, eliminar={total_delete}, '
            f'duplicados_panel={total_deduped}.'
        ),
        'info',
    )

    if details:
        flash(' | '.join(details[:8]), 'info')
    if len(details) > 8:
        flash(f'Se omitieron {len(details) - 8} servidor(es) en el detalle por longitud.', 'secondary')
    if errors:
        flash('Servidores no previsualizados: ' + ' | '.join(errors[:8]), 'warning')

    return redirect(url_for('admin.servers'))


@admin_bp.route('/servers/<int:server_id>/sync-preview', methods=['POST'])
@admin_required
def sync_preview_server_users(server_id: int):
    server = db.session.get(Server, server_id)
    if not server:
        flash('Servidor no encontrado.', 'danger')
        return redirect(url_for('admin.servers'))

    svc = SSHService(server)
    ok, remote_users, err = svc.list_users_for_sync()
    if not ok:
        flash(f'No se pudo previsualizar {server.name}: {err}', 'warning')
        return redirect(url_for('admin.servers'))

    stats = _build_panel_sync_preview(server, remote_users)
    flash(
        (
            f"Previsualizacion panel -> '{server.name}': panel={stats['panel_total']}, VPS={stats['remote_total']}, "
            f"crear={stats['to_create']}, actualizar={stats['to_update']}, eliminar={stats['to_delete']}, "
            f"duplicados_panel={stats['deduped_panel']}."
        ),
        'info',
    )
    return redirect(url_for('admin.servers'))


@admin_bp.route('/servers/panel-timezone', methods=['POST'])
@admin_required
def set_panel_timezone():
    tz = request.form.get('panel_timezone', '').strip()
    online_interval_seconds = request.form.get('online_check_interval_seconds', 5, type=int) or 5
    online_interval_seconds = max(1, min(300, online_interval_seconds))
    limiter_interval_seconds = request.form.get('limiter_interval_seconds', 5, type=int) or 5
    limiter_interval_seconds = max(2, min(60, limiter_interval_seconds))
    propagate = request.form.get('propagate_to_servers') == '1'
    if not tz or not _valid_timezone(tz):
        flash('Zona horaria inválida.', 'danger')
        return redirect(url_for('admin.servers'))
    _set_panel_timezone(tz)
    _set_online_check_interval_seconds(online_interval_seconds)
    _set_limiter_interval_seconds(limiter_interval_seconds)
    if propagate:
        for sv in Server.query.all():
            sv.timezone = tz
        db.session.commit()
        flash(
            f"Zona horaria del panel y de todos los servidores actualizada a {tz}. "
            f"Panel se actualiza cada {online_interval_seconds} segundo(s). "
            f"Límites se aplican cada {limiter_interval_seconds} segundo(s).",
            'success',
        )
    else:
        flash(
            f"Zona horaria del panel actualizada a {tz}. "
            f"Panel se actualiza cada {online_interval_seconds} segundo(s). "
            f"Límites se aplican cada {limiter_interval_seconds} segundo(s).",
            'success',
        )
    return redirect(url_for('admin.servers'))


@admin_bp.route('/servers/<int:server_id>/delete', methods=['POST'])
@admin_required
def delete_server(server_id: int):
    server = db.session.get(Server, server_id)
    if not server:
        flash('Servidor no encontrado.', 'danger')
        return redirect(url_for('admin.servers'))

    server_name = server.name
    target_server = _pick_server_transfer_target(server.id)
    if not target_server:
        flash('No se puede eliminar: necesitas al menos otro servidor activo para transferir revendedores y usuarios VPN.', 'danger')
        return redirect(url_for('admin.servers'))

    try:
        ok_transfer, stats, err_transfer, remote_sync_payloads = _transfer_server_records_db_only(server, target_server)
        if not ok_transfer:
            raise RuntimeError(
                f"No se pudo transferir el contenido del servidor al destino '{target_server.name}': {err_transfer}"
            )

        remaining_resellers = Reseller.query.filter_by(server_id=server.id).count()
        remaining_users = VpnUser.query.filter_by(server_id=server.id).count()
        if remaining_resellers or remaining_users:
            raise RuntimeError(
                (
                    'Transferencia incompleta en base de datos. '
                    f'Revendedores restantes={remaining_resellers}, usuarios restantes={remaining_users}.'
                )
            )

        Server.query.filter_by(id=server.id).delete(synchronize_session=False)
        db.session.commit()

        sync_id = _start_server_delete_background_sync(
            source_server_name=server_name,
            target_server_id=target_server.id,
            target_server_name=target_server.name,
            user_payloads=remote_sync_payloads,
        )
    except Exception as exc:
        db.session.rollback()
        current_app.logger.exception('Error eliminando servidor id=%s', server_id)
        flash(
            (
                f"No se pudo eliminar '{server_name}'. La transferencia hacia '{target_server.name}' fue cancelada: "
                f"{str(exc)[:180]}"
            ),
            'danger',
        )
        return redirect(url_for('admin.servers'))

    parts = [f"Servidor '{server_name}' eliminado correctamente."]
    parts.append(f"Destino: {target_server.name}.")
    parts.append(f"Revendedores transferidos exitosamente: {stats['resellers']}.")
    parts.append(f"Usuarios VPN transferidos exitosamente: {stats['users']}.")
    if stats['admin_users']:
        parts.append(f"Usuarios del administrador reasignados: {stats['admin_users']}.")
    if stats['active_sync_queued']:
        parts.append(
            f"Sincronización remota en segundo plano iniciada para {stats['active_sync_queued']} usuario(s) activo(s)."
        )
        parts.append(f"Seguimiento de sincronización: {sync_id}.")
    if stats['inactive_moved']:
        parts.append(f"Usuarios inactivos movidos solo en base de datos: {stats['inactive_moved']}.")
    flash(' '.join(parts), 'success')
    return redirect(url_for('admin.servers'))


@admin_bp.route('/servers/reconcile-resellers', methods=['POST'])
@admin_required
def reconcile_resellers():
    """Mueve Reseller.server_id al servidor donde tiene más usuarios activos."""
    rows = (
        db.session.query(VpnUser.reseller_id, VpnUser.server_id, func.count(VpnUser.id))
        .join(Reseller, VpnUser.reseller_id == Reseller.id)
        .filter(VpnUser.is_active.is_(True))
        .filter(or_(Reseller.note.is_(None), Reseller.note != SYSTEM_ADMIN_RESELLER_NOTE))
        .group_by(VpnUser.reseller_id, VpnUser.server_id)
        .all()
    )

    best_server: dict[int, tuple[int, int]] = {}
    for reseller_id, server_id, count in rows:
        prev = best_server.get(int(reseller_id))
        if prev is None or int(count) > prev[1]:
            best_server[int(reseller_id)] = (int(server_id), int(count))

    if not best_server:
        flash('No hay revendedores con usuarios activos para reconciliar.', 'info')
        return redirect(url_for('admin.servers'))

    resellers = Reseller.query.filter(Reseller.id.in_(list(best_server.keys()))).all()
    moved = 0
    users_aligned = 0
    for reseller in resellers:
        target_server_id, _ = best_server[int(reseller.id)]
        if int(reseller.server_id or 0) != target_server_id:
            reseller.server_id = target_server_id
            moved += 1

        aligned = (
            VpnUser.query
            .filter(VpnUser.reseller_id == reseller.id)
            .filter(VpnUser.is_active.is_(True))
            .filter(VpnUser.server_id != target_server_id)
            .update({VpnUser.server_id: target_server_id}, synchronize_session=False)
        )
        users_aligned += int(aligned or 0)

    if moved or users_aligned:
        db.session.commit()
        flash(
            f'Reconciliación completada: revendedores_movidos={moved}, usuarios_alineados={users_aligned}.',
            'success',
        )
    else:
        flash('Todo reconciliado: no se detectó deriva revendedor/usuario.', 'info')

    return redirect(url_for('admin.servers'))


@admin_bp.route('/servers/delete-sync-status', methods=['GET'])
@admin_required
def server_delete_sync_status():
    return jsonify({'ok': True, 'items': _list_delete_sync_status()})


@admin_bp.route('/servers/user-sync-status', methods=['GET'])
@admin_required
def server_user_sync_status():
    return jsonify({'ok': True, 'items': _list_user_sync_status()})


@admin_bp.route('/servers/<int:server_id>/test', methods=['POST'])
@admin_required
def test_server(server_id: int):
    server = db.session.get(Server, server_id)
    if not server:
        return jsonify({'ok': False, 'msg': 'Servidor no encontrado'})
    svc = SSHService(server)
    ok, msg = svc.test_connection()
    if not ok:
        return jsonify({'ok': False, 'msg': msg})

    ports_msg = ''
    if current_app.config.get('AUTO_OPEN_PORTS_ON_FIRST_CONNECT', True):
        opened_ids = _get_first_connect_opened_ids()
        if server.id not in opened_ids:
            opened, failed = _open_initial_ports_once(server, svc)

            if opened and not failed:
                ports_msg = f" Puertos abiertos automaticamente: {', '.join(opened)}"
            elif opened and failed:
                ports_msg = (
                    f" Apertura parcial: abiertos {', '.join(opened)}. "
                    f"Fallidos: {' | '.join(failed)}"
                )
            elif failed:
                ports_msg = f" No se pudieron abrir puertos: {' | '.join(failed)}"

    return jsonify({'ok': True, 'msg': f'Conexión exitosa ✓{ports_msg}'})


@admin_bp.route('/servers/<int:server_id>/ports-status', methods=['GET'], strict_slashes=False)
@admin_bp.route('/servers/ports-status/<int:server_id>', methods=['GET'])
@admin_required
def server_ports_status(server_id: int):
    try:
        server = db.session.get(Server, server_id)
        if not server:
            return jsonify({'ok': False, 'msg': 'Servidor no encontrado', 'status': {}}), 404

        svc = SSHService(server)
        ok, details, err = svc.get_port_modules_details()
        if not ok:
            return jsonify({'ok': False, 'msg': err, 'status': {}}), 200

        status = {k: bool((v or {}).get('active')) for k, v in (details or {}).items()}
        return jsonify({'ok': True, 'status': status, 'details': details})
    except Exception as ex:
        current_app.logger.exception('Error consultando estado de puertos en server id=%s', server_id)
        return jsonify({'ok': False, 'msg': f'Error interno: {str(ex)[:180]}', 'status': {}}), 500



@admin_bp.route('/servers/<int:server_id>/reboot', methods=['POST'])
@admin_required
def reboot_server(server_id: int):
    server = db.session.get(Server, server_id)
    if not server:
        flash('Servidor no encontrado.', 'danger')
        return redirect(url_for('admin.servers'))

    svc = SSHService(server)
    ok, msg = svc.reboot_server()
    if ok:
        flash(
            f"Reinicio enviado a '{server.name}'. Espera 1-2 minutos para que vuelva en línea.",
            'success',
        )
    else:
        flash(f"No se pudo reiniciar '{server.name}': {msg}", 'danger')
    return redirect(url_for('admin.servers'))


@admin_bp.route('/servers/<int:server_id>/open-port', methods=['POST'], strict_slashes=False)
@admin_bp.route('/servers/open-port/<int:server_id>', methods=['POST'])
@admin_required
def open_server_port(server_id: int):
    wants_json = request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    def _json_or_redirect(ok: bool, msg: str, category: str = 'success'):
        if wants_json:
            return jsonify({'ok': ok, 'msg': msg}), (200 if ok else 400)
        flash(msg, category)
        return redirect(url_for('admin.servers'))

    try:
        server = db.session.get(Server, server_id)
        if not server:
            return _json_or_redirect(False, 'Servidor no encontrado.', 'danger')

        module = (request.form.get('module') or '').strip().lower()
        action = (request.form.get('action') or 'open').strip().lower()
        open_mode = (request.form.get('open_mode') or 'port_and_module').strip().lower()
        try:
            port = int(request.form.get('port', '0') or 0)
        except ValueError:
            port = 0

        if module not in {'http_vpnpro', 'ssl_tunnel', 'websocket_tunnel', 'badvpn_udp', 'checkuser'}:
            return _json_or_redirect(False, 'Modulo de puertos invalido.', 'danger')

        if action not in {'open', 'close'}:
            return _json_or_redirect(False, 'Accion invalida.', 'danger')

        if open_mode not in {'port_and_module', 'port_only'}:
            open_mode = 'port_and_module'

        if action == 'close':
            svc = SSHService(server)
            if module == 'badvpn_udp':
                ok, msg = svc.disable_badvpn_udpgw()
            elif module == 'checkuser':
                ok, msg = svc.uninstall_checkuser()
            elif module == 'http_vpnpro':
                ok, msg = svc.disable_http_vpnpro_tunnel()
            elif module == 'ssl_tunnel':
                ok, msg = svc.disable_ssl_tunnel()
            elif module == 'websocket_tunnel':
                ok, msg = svc.disable_websocket_tunnel()
            else:
                return _json_or_redirect(False, f"[{server.name}] Cierre de módulo no implementado.", 'danger')

            if ok:
                return _json_or_redirect(True, f"[{server.name}] {msg}", 'success')
            else:
                return _json_or_redirect(False, f"[{server.name}] Error al cerrar puerto: {msg}", 'danger')

        if port < 1 or port > 65535:
            return _json_or_redirect(False, 'Puerto invalido. Debe estar entre 1 y 65535.', 'danger')

        svc = SSHService(server)
        open_protocols = ['udp'] if module == 'badvpn_udp' else ['tcp']
        fw_ok, fw_msg = svc.open_port_rules(port, open_protocols)
        if not fw_ok:
            return _json_or_redirect(False, f"[{server.name}] No se pudo abrir el puerto en firewall: {fw_msg}", 'danger')

        if open_mode == 'port_only':
            return _json_or_redirect(True, f"[{server.name}] {fw_msg} Modo aplicado: solo apertura de puerto.", 'success')

        if module == 'http_vpnpro':
            ok, msg = svc.setup_http_vpnpro_tunnel(port)
        elif module == 'ssl_tunnel':
            ok, msg = svc.setup_ssl_tunnel(port)
        elif module == 'badvpn_udp':
            ok, msg = svc.setup_badvpn_udpgw(port)
        elif module == 'checkuser':
            ok, msg = svc.install_checkuser(port)
        else:
            ok, msg = svc.setup_websocket_tunnel(port)
        if ok:
            return _json_or_redirect(True, f"[{server.name}] {fw_msg} {msg}", 'success')
        else:
            return _json_or_redirect(False, f"[{server.name}] {fw_msg} No se pudo activar el modulo ({msg}).", 'warning')
    except Exception as ex:
        current_app.logger.exception('Error en open_server_port server id=%s', server_id)
        return _json_or_redirect(False, f'Error interno: {str(ex)[:180]}', 'danger')


@admin_bp.route('/servers/<int:server_id>/sync-users', methods=['POST'])
@admin_required
def sync_server_users(server_id: int):
    server = db.session.get(Server, server_id)
    if not server:
        flash('Servidor no encontrado.', 'danger')
        return redirect(url_for('admin.servers'))

    # Estimate user count for progress tracking
    panel_users = (
        VpnUser.query
        .join(Reseller, VpnUser.reseller_id == Reseller.id)
        .filter(or_(VpnUser.server_id == server.id, Reseller.server_id == server.id))
        .filter(VpnUser.is_active == True)
        .count()
    )

    # Start background sync and return immediately
    sync_id = _start_user_sync_background(
        server_id=server.id,
        server_name=server.name,
        total_users=panel_users,
        sync_type='single',
    )

    flash(
        f"Sincronización de usuarios en '{server.name}' iniciada en segundo plano (id: {sync_id[-8:]}).",
        'info',
    )
    return redirect(url_for('admin.servers'))


@admin_bp.route('/servers/sync-users-all', methods=['POST'])
@admin_required
def sync_all_servers_users():
    servers = Server.query.filter_by(is_active=True).all()
    servers = sorted(servers, key=_server_logical_sort_key)
    if not servers:
        flash('No hay servidores activos para sincronizar.', 'warning')
        return redirect(url_for('admin.servers'))

    # Estimate total user count
    total_users = VpnUser.query.filter(VpnUser.is_active == True).count()

    # Start background sync and return immediately
    sync_id = _start_user_sync_background(
        server_id=0,  # 0 means all servers
        server_name='Todos los servidores',
        total_users=total_users,
        sync_type='all',
    )

    flash(
        f'Sincronización masiva de usuarios en segundo plano iniciada para {len(servers)} servidor(es) (id: {sync_id[-8:]}).',
        'info',
    )
    return redirect(url_for('admin.servers'))


@admin_bp.route('/servers/<int:server_id>/toggle', methods=['POST'])
@admin_required
def toggle_server(server_id: int):
    server = db.session.get(Server, server_id)
    if server:
        server.is_active = not server.is_active
        db.session.commit()
        state = 'activado' if server.is_active else 'desactivado'
        flash(f"Servidor '{server.name}' {state}.", 'success')
    return redirect(url_for('admin.servers'))


@admin_bp.route('/servers/<int:server_id>/transfer-users', methods=['GET', 'POST'])
@admin_required
def transfer_server_users(server_id: int):
    if request.method != 'POST':
        flash('Acción inválida. Usa el botón Transferir usuarios desde la tabla de servidores.', 'warning')
        return redirect(url_for('admin.servers'))

    try:
        source_server = db.session.get(Server, server_id)
        if not source_server:
            flash('Servidor origen no encontrado.', 'danger')
            return redirect(url_for('admin.servers'))

        target_server_id = request.form.get('target_server_id', type=int)
        if not target_server_id:
            flash('Debes seleccionar un servidor destino.', 'danger')
            return redirect(url_for('admin.servers'))

        if int(target_server_id) == int(source_server.id):
            flash('El servidor destino debe ser diferente al servidor origen.', 'warning')
            return redirect(url_for('admin.servers'))

        target_server = db.session.get(Server, target_server_id)
        if not target_server or not target_server.is_active:
            flash('Servidor destino inválido o inactivo.', 'danger')
            return redirect(url_for('admin.servers'))

        source_user_ids = [
            int(uid)
            for (uid,) in (
                db.session.query(VpnUser.id)
                .filter(VpnUser.server_id == source_server.id)
                .order_by(VpnUser.id.asc())
                .all()
            )
        ]

        source_reseller_ids = [
            int(rid)
            for (rid,) in (
                db.session.query(Reseller.id)
                .filter(Reseller.server_id == source_server.id)
                .filter(or_(Reseller.note.is_(None), Reseller.note != SYSTEM_ADMIN_RESELLER_NOTE))
                .all()
            )
        ]

        if not source_user_ids and not source_reseller_ids:
            flash(
                (
                    f"No hay usuarios ni revendedores para transferir desde "
                    f"'{source_server.name} [id={source_server.id}]'."
                ),
                'info',
            )
            return redirect(url_for('admin.servers'))

        sync_id = _start_transfer_users_background_sync(source_server, target_server, source_user_ids)

        if source_user_ids:
            summary = (
                f"usuarios={len(source_user_ids)}, revendedores={len(source_reseller_ids)}"
            )
        else:
            summary = f"usuarios=0, revendedores={len(source_reseller_ids)}"

        flash(
            (
                f"Transferencia encolada '{source_server.name} [id={source_server.id}]' -> "
                f"'{target_server.name} [id={target_server.id}]'. "
                f"Resumen: {summary}. "
                f"ID: {sync_id}. Se procesará en segundo plano para evitar timeout."
            ),
            'info',
        )

        return redirect(url_for('admin.servers'))
    except Exception as ex:
        db.session.rollback()
        current_app.logger.exception('Error en transfer_server_users server_id=%s', server_id)
        flash(f'Error interno al transferir usuarios: {str(ex)[:180]}', 'danger')
        return redirect(url_for('admin.servers'))


@admin_bp.route('/servers/<int:server_id>/transfer-users/preview', methods=['GET'])
@admin_required
def transfer_server_users_preview(server_id: int):
    source_server = db.session.get(Server, server_id)
    if not source_server:
        return jsonify({'ok': False, 'msg': 'Servidor origen no encontrado.'}), 404

    target_server_id = request.args.get('target_server_id', type=int)
    if not target_server_id:
        return jsonify({'ok': False, 'msg': 'Debes indicar target_server_id.'}), 400

    if int(target_server_id) == int(source_server.id):
        return jsonify({'ok': False, 'msg': 'El destino debe ser diferente al origen.'}), 400

    target_server = db.session.get(Server, target_server_id)
    if not target_server:
        return jsonify({'ok': False, 'msg': 'Servidor destino no encontrado.'}), 404

    stats = _build_transfer_users_preview(source_server, target_server)
    return jsonify({'ok': True, 'stats': stats})


# ──────────────────────────────────────────────────────────
# Resellers
# ──────────────────────────────────────────────────────────

def _resolve_page_params(default_per_page: int = 200, max_per_page: int = 500) -> tuple[int, int]:
    page = request.args.get('page', 1, type=int) or 1
    per_page = request.args.get('per_page', default_per_page, type=int) or default_per_page
    page = max(1, int(page))
    per_page = max(25, min(max_per_page, int(per_page)))
    return page, per_page

@admin_bp.route('/resellers', methods=['GET', 'POST'])
@admin_required
def resellers():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        email = request.form.get('email', '').strip()
        server_id = request.form.get('server_id', type=int)
        max_connections = request.form.get('max_connections', 1, type=int)
        panel_credits = request.form.get('panel_credits', 0, type=int)
        note = request.form.get('note', '').strip()

        if not username or not password or not server_id:
            flash('Usuario, contraseña y servidor son obligatorios.', 'danger')
        elif not VPN_USERNAME_PATTERN.fullmatch(username):
            flash('El usuario del revendedor debe usar formato MAYUSCULAS-NOMBRE-APELLIDO.', 'danger')
        elif Reseller.query.filter_by(username=username).first():
            flash(f"El usuario '{username}' ya existe.", 'danger')
        else:
            r = Reseller(
                username=username, email=email,
                server_id=server_id,
                max_connections=max(1, max_connections or 1),
                panel_credits=max(0, panel_credits or 0),
                note=note,
            )
            r.set_password(password)
            db.session.add(r)
            db.session.flush()
            if (r.panel_credits or 0) > 0:
                _log_credit_movement(r, r.panel_credits, 'Credito inicial asignado por Admin')
            db.session.commit()
            flash(f"Revendedor '{username}' creado.", 'success')
        return redirect(url_for('admin.resellers'))

    page, per_page = _resolve_page_params(default_per_page=150, max_per_page=400)
    filter_q = (request.args.get('q', '') or '').strip()
    filter_server_id = request.args.get('server_id', type=int)
    filter_state = (request.args.get('state', '') or '').strip().lower()

    resellers_query = (
        Reseller.query
        .options(joinedload(Reseller.server))
        .filter(Reseller.note != SYSTEM_ADMIN_RESELLER_NOTE)
    )

    if filter_q:
        q_upper = filter_q.upper()
        resellers_query = resellers_query.filter(
            or_(
                func.upper(Reseller.username).like(f'%{q_upper}%'),
                func.upper(Reseller.email).like(f'%{q_upper}%'),
            )
        )
    if filter_server_id:
        resellers_query = resellers_query.filter(Reseller.server_id == int(filter_server_id))
    if filter_state == 'active':
        resellers_query = resellers_query.filter(Reseller.is_active.is_(True))
    elif filter_state == 'inactive':
        resellers_query = resellers_query.filter(Reseller.is_active.is_(False))

    resellers_pagination = resellers_query.order_by(Reseller.username).paginate(page=page, per_page=per_page, error_out=False)
    all_servers = Server.query.filter_by(is_active=True).all()
    all_servers = sorted(all_servers, key=_server_logical_sort_key)
    credit_logs = (
        CreditMovement.query
        .options(
            load_only(
                CreditMovement.id,
                CreditMovement.delta,
                CreditMovement.balance_after,
                CreditMovement.reason,
                CreditMovement.created_at,
                CreditMovement.reseller_id,
            ),
            joinedload(CreditMovement.reseller).load_only(Reseller.id, Reseller.username, Reseller.note),
        )
        .join(Reseller, CreditMovement.reseller_id == Reseller.id)
        .filter(Reseller.note != SYSTEM_ADMIN_RESELLER_NOTE)
        .order_by(CreditMovement.created_at.desc())
        .limit(30)
        .all()
    )
    return render_template(
        'admin/resellers.html',
        resellers=list(resellers_pagination.items),
        page=page,
        per_page=per_page,
        total=resellers_pagination.total,
        pages=resellers_pagination.pages,
        has_prev=resellers_pagination.has_prev,
        has_next=resellers_pagination.has_next,
        filter_q=filter_q,
        filter_server_id=filter_server_id,
        filter_state=filter_state,
        servers=all_servers,
        credit_logs=credit_logs,
    )


@admin_bp.route('/resellers/<int:reseller_id>/edit', methods=['POST'])
@admin_required
def edit_reseller(reseller_id: int):
    r = db.session.get(Reseller, reseller_id)
    if not r:
        flash('Revendedor no encontrado.', 'danger')
        return redirect(url_for('admin.resellers'))

    old_credits = r.panel_credits or 0
    new_password = request.form.get('password', '')
    previous_server_id = int(r.server_id or 0)
    r.email = request.form.get('email', '').strip()
    r.server_id = request.form.get('server_id', type=int) or r.server_id
    r.max_connections = max(1, request.form.get('max_connections', r.max_connections, type=int) or 1)
    r.panel_credits = max(0, request.form.get('panel_credits', r.panel_credits, type=int) or 0)
    r.note = request.form.get('note', '').strip()
    if new_password:
        r.set_password(new_password)

    if int(r.server_id or 0) != previous_server_id:
        (
            VpnUser.query
            .filter(VpnUser.reseller_id == r.id)
            .update({VpnUser.server_id: r.server_id}, synchronize_session=False)
        )

    delta = (r.panel_credits or 0) - old_credits
    if delta != 0:
        action = 'Recarga manual' if delta > 0 else 'Descuento manual'
        _log_credit_movement(r, delta, f"{action} por admin {current_user.username}")

    db.session.commit()
    flash(f"Revendedor '{r.username}' actualizado.", 'success')
    return redirect(url_for('admin.resellers'))


@admin_bp.route('/resellers/<int:reseller_id>/toggle', methods=['POST'])
@admin_required
def toggle_reseller(reseller_id: int):
    r = db.session.get(Reseller, reseller_id)
    if r:
        r.is_active = not r.is_active
        db.session.commit()
        state = 'activado' if r.is_active else 'desactivado'
        flash(f"Revendedor '{r.username}' {state}.", 'success')
    return redirect(url_for('admin.resellers'))


@admin_bp.route('/resellers/<int:reseller_id>/delete', methods=['POST'])
@admin_required
def delete_reseller(reseller_id: int):
    r = db.session.get(Reseller, reseller_id)
    if not r:
        flash('Revendedor no encontrado.', 'danger')
        return redirect(url_for('admin.resellers'))
    if r.note == SYSTEM_ADMIN_RESELLER_NOTE:
        flash('No se puede eliminar el propietario interno del administrador.', 'danger')
        return redirect(url_for('admin.resellers'))

    reseller_name = r.username

    moved_users = 0
    users_to_move = VpnUser.query.filter_by(reseller_id=r.id).all()
    admin_owner_by_server: dict[int, Reseller] = {}
    default_server_id = r.server_id
    if not db.session.get(Server, default_server_id):
        fallback_server = next(iter(sorted(Server.query.filter_by(is_active=True).all(), key=_server_logical_sort_key)), None)
        if fallback_server:
            default_server_id = fallback_server.id

    def _owner_for_server(server_id: int) -> Reseller:
        owner = admin_owner_by_server.get(server_id)
        if owner:
            return owner

        reserved_usernames = {
            f'Admin-{server_id}',
            f'__ADMIN_OWNER_{server_id}__',
        }
        if r.server_id == server_id and r.username in reserved_usernames:
            # Legacy edge case: reserved username is occupied by a normal reseller.
            # Rename first so internal owner creation cannot hit UNIQUE(username).
            r.username = f'DELETED-{r.id}-{secrets.token_hex(2)}'
            db.session.flush()

        owner = _get_or_create_system_reseller(server_id)

        if owner.id == r.id:
            r.username = f'DELETED-{r.id}-{secrets.token_hex(2)}'
            db.session.flush()
            owner = _get_or_create_system_reseller(server_id)

        admin_owner_by_server[server_id] = owner
        return owner

    for u in users_to_move:
        target_server_id = u.server_id if db.session.get(Server, u.server_id) else default_server_id
        admin_owner = _owner_for_server(target_server_id)
        if u.server_id != target_server_id:
            u.server_id = target_server_id
        u.reseller = admin_owner
        moved_users += 1

    try:
        # Delete movement rows through ORM state to avoid stale rowcount mismatches.
        for movement in list(r.credit_movements):
            db.session.delete(movement)

        db.session.delete(r)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        current_app.logger.exception('Error eliminando revendedor id=%s: %s', reseller_id, exc)
        flash('No se pudo eliminar el revendedor por un error interno. Revisa logs del panel.', 'danger')
        return redirect(url_for('admin.resellers'))

    if moved_users > 0:
        flash(
            f"Revendedor '{reseller_name}' eliminado. {moved_users} usuario(s) fueron transferidos al Administrador.",
            'success',
        )
    else:
        flash(f"Revendedor '{reseller_name}' eliminado.", 'success')
    return redirect(url_for('admin.resellers'))


@admin_bp.route('/resellers/<int:reseller_id>/add-credits', methods=['POST'])
@admin_required
def add_reseller_credits(reseller_id: int):
    r = db.session.get(Reseller, reseller_id)
    if not r:
        flash('Revendedor no encontrado.', 'danger')
        return redirect(url_for('admin.resellers'))

    try:
        amount = int(request.form.get('amount', 0))
    except (ValueError, TypeError):
        flash('Cantidad de créditos inválida.', 'danger')
        return redirect(url_for('admin.resellers'))

    operation = (request.form.get('operation') or 'add').strip().lower()
    if operation not in {'add', 'subtract'}:
        flash('Operación de créditos inválida.', 'danger')
        return redirect(url_for('admin.resellers'))

    if amount <= 0:
        flash('La cantidad debe ser mayor a 0.', 'danger')
        return redirect(url_for('admin.resellers'))

    old_balance = r.panel_credits or 0

    if operation == 'subtract' and amount > old_balance:
        flash(
            f"No puedes descontar {amount} crédito(s) a '{r.username}' porque su saldo actual es {old_balance}.",
            'danger',
        )
        return redirect(url_for('admin.resellers'))

    delta = amount if operation == 'add' else -amount
    r.panel_credits = old_balance + delta

    _log_credit_movement(
        r,
        delta,
        (
            f"Recarga de {amount} crédito(s) por admin {current_user.username}"
            if operation == 'add'
            else f"Descuento de {amount} crédito(s) por admin {current_user.username}"
        ),
    )

    db.session.commit()
    if operation == 'add':
        flash(
            f"Agregados {amount} créditos a '{r.username}'. Saldo anterior: {old_balance} → Nuevo saldo: {r.panel_credits}",
            'success',
        )
    else:
        flash(
            f"Descontados {amount} créditos a '{r.username}'. Saldo anterior: {old_balance} → Nuevo saldo: {r.panel_credits}",
            'success',
        )
    return redirect(url_for('admin.resellers'))


# ──────────────────────────────────────────────────────────
# VPN Users (admin view — all users)
# ──────────────────────────────────────────────────────────

@admin_bp.route('/users')
@admin_required
def users():
    page, per_page = _resolve_page_params(default_per_page=200, max_per_page=500)
    filter_q = (request.args.get('q', '') or '').strip()
    filter_server_id = request.args.get('server_id', type=int)
    filter_reseller_id = request.args.get('reseller_id', type=int)
    filter_state = (request.args.get('state', '') or '').strip().lower()
    now_utc = datetime.utcnow()

    users_query = (
        VpnUser.query
        .options(
            load_only(
                VpnUser.id,
                VpnUser.username,
                VpnUser._password,
                VpnUser.connection_limit,
                VpnUser.expiry_date,
                VpnUser.is_blocked,
                VpnUser.is_active,
                VpnUser.server_id,
                VpnUser.reseller_id,
                VpnUser.created_at,
            ),
            joinedload(VpnUser.server).load_only(Server.id, Server.name),
            joinedload(VpnUser.reseller).load_only(Reseller.id, Reseller.username, Reseller.note),
        )
        .filter_by(is_active=True)
    )

    if filter_q:
        q_upper = filter_q.upper()
        users_query = users_query.filter(func.upper(VpnUser.username).like(f'%{q_upper}%'))
    if filter_server_id:
        users_query = users_query.filter(VpnUser.server_id == int(filter_server_id))
    if filter_reseller_id:
        users_query = users_query.filter(VpnUser.reseller_id == int(filter_reseller_id))
    if filter_state == 'blocked':
        users_query = users_query.filter(VpnUser.is_blocked.is_(True))
    elif filter_state == 'expired':
        users_query = users_query.filter(VpnUser.expiry_date < now_utc)
    elif filter_state == 'active':
        users_query = users_query.filter(VpnUser.is_blocked.is_(False), VpnUser.expiry_date >= now_utc)

    users_pagination = users_query.order_by(VpnUser.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    all_resellers = (
        Reseller.query
        .options(load_only(Reseller.id, Reseller.username, Reseller.note))
        .filter(Reseller.is_active.is_(True), Reseller.note != SYSTEM_ADMIN_RESELLER_NOTE)
        .all()
    )
    all_servers = Server.query.options(load_only(Server.id, Server.name)).filter_by(is_active=True).all()
    all_servers = sorted(all_servers, key=_server_logical_sort_key)
    return render_template(
        'admin/users.html',
        users=list(users_pagination.items),
        page=page,
        per_page=per_page,
        total=users_pagination.total,
        pages=users_pagination.pages,
        has_prev=users_pagination.has_prev,
        has_next=users_pagination.has_next,
        filter_q=filter_q,
        filter_server_id=filter_server_id,
        filter_reseller_id=filter_reseller_id,
        filter_state=filter_state,
        resellers=all_resellers,
        servers=all_servers,
        package_options=PACKAGE_OPTIONS,
        online_check_interval_ms=get_online_check_interval_ms(),
    )


def _build_admin_users_online_payload(
    enforce_auto: bool,
    requested_user_ids: set[int] | None = None,
    requested_server_id: int | None = None,
    prefer_fresh_snapshot: bool = False,
) -> dict[str, object]:
    active_users_query = (
        db.session.query(
            VpnUser.id,
            VpnUser.server_id,
            VpnUser.username,
            VpnUser.connection_limit,
            VpnUser.is_blocked,
        )
        .filter(VpnUser.is_active.is_(True))
    )
    if requested_user_ids:
        active_users_query = active_users_query.filter(VpnUser.id.in_(list(requested_user_ids)))
    if requested_server_id:
        active_users_query = active_users_query.filter(VpnUser.server_id == int(requested_server_id))

    active_users = active_users_query.all()
    if not active_users:
        return {
            'ok': True,
            'online': {},
            'total_online_detected': 0,
            'errors': [],
            'trimmed_sessions': [],
        }

    users_by_server: dict[int, list[tuple[int, str, int, bool]]] = {}
    for user_id, server_id, username, connection_limit, is_blocked in active_users:
        users_by_server.setdefault(server_id, []).append((user_id, username, connection_limit, bool(is_blocked)))

    servers_map: dict[int, Server] = {
        s.id: s for s in Server.query.filter(Server.id.in_(list(users_by_server.keys()))).all()
    }

    online_by_user_id: dict[str, dict[str, int]] = {}
    total_online_detected = 0
    errors: list[str] = []
    trimmed_sessions: list[str] = []

    for server_id, server_users in users_by_server.items():
        server = servers_map.get(server_id)
        if not server:
            continue

        snapshot = None
        if not prefer_fresh_snapshot:
            snapshot = get_cached_online_snapshot(server_id)
        if snapshot is not None:
            normalized = dict(snapshot.get('online_map') or {})
            normalized_devices = dict(snapshot.get('device_map') or {})
            normalized_connected_seconds = dict(snapshot.get('connected_seconds_map') or {})
        else:
            svc = SSHService(server)
            ok, online_map, device_map, connected_seconds_map, err = svc.get_online_user_snapshot()
            if not ok:
                errors.append(f"{server.name}: {err}")
                continue

            normalized = {k.strip().upper(): v for k, v in (online_map or {}).items()}
            normalized_devices = (
                {k.strip().upper(): v for k, v in (device_map or {}).items()}
                if device_map is not None
                else {}
            )
            normalized_connected_seconds = {
                k.strip().upper(): v for k, v in (connected_seconds_map or {}).items()
            }
            cache_online_snapshot(
                server_id,
                normalized,
                device_map=normalized_devices,
                connected_seconds_map=normalized_connected_seconds,
            )

        if enforce_auto:
            svc = SSHService(server)
            trimmed_now, block_errors = auto_block_users_exceeding_limit(
                server_users,
                normalized,
                svc,
                device_online_map=normalized_devices,
            )
            if trimmed_now:
                trimmed_sessions.extend(trimmed_now)
            if trimmed_now:
                ok_refresh, refreshed_online_map, refreshed_device_map, refreshed_connected_seconds_map, refresh_err = svc.get_online_user_snapshot()
                if ok_refresh:
                    normalized = {k.strip().upper(): v for k, v in (refreshed_online_map or {}).items()}
                else:
                    errors.append(f"{server.name}: No se pudo refrescar sesiones tras control automatico: {refresh_err}")

                if ok_refresh:
                    normalized_devices = {
                        k.strip().upper(): v for k, v in (refreshed_device_map or {}).items()
                    }
                    normalized_connected_seconds = {
                        k.strip().upper(): v for k, v in (refreshed_connected_seconds_map or {}).items()
                    }

                cache_online_snapshot(
                    server_id,
                    normalized,
                    device_map=normalized_devices,
                    connected_seconds_map=normalized_connected_seconds,
                )
            if block_errors:
                errors.extend([f"{server.name}: {detail}" for detail in block_errors])

        for user_id, username, connection_limit, _is_blocked in server_users:
            normalized_user = username.strip().upper()
            sessions_count = max(0, int(normalized.get(normalized_user, 0) or 0))
            devices_count = max(0, int(normalized_devices.get(normalized_user, 0) or 0))
            observed_count = calculate_observed_connection_count(
                sessions_count,
                devices_count,
                has_device_metric=True,
            )
            if observed_count > 0:
                total_online_detected += observed_count
                online_by_user_id[str(user_id)] = {
                    'sessions': observed_count,
                    'limit': connection_limit,
                    'connected_seconds': max(0, int(normalized_connected_seconds.get(normalized_user, 0) or 0)),
                }

    return {
        'ok': True,
        'online': online_by_user_id,
        'total_online_detected': total_online_detected,
        'errors': errors,
        'trimmed_sessions': trimmed_sessions,
    }


@admin_bp.route('/users/online')
@admin_required
def online_users():
    enforce_auto = parse_query_bool(request.args.get('enforce', '1'), default=True)
    requested_user_ids = _parse_requested_user_ids()
    requested_server_id = _parse_requested_server_id()
    prefer_fresh_snapshot = parse_query_bool(request.args.get('fresh', '0'), default=False)
    can_use_endpoint_cache = (
        (not requested_user_ids)
        and (requested_server_id is None)
        and (not prefer_fresh_snapshot)
    )
    if not enforce_auto and can_use_endpoint_cache:
        cached_payload = cache_get('admin-users-online-snapshot')
        if isinstance(cached_payload, dict):
            return jsonify(cached_payload)

    payload = _build_admin_users_online_payload(
        enforce_auto,
        requested_user_ids=requested_user_ids,
        requested_server_id=requested_server_id,
        prefer_fresh_snapshot=prefer_fresh_snapshot,
    )
    if not enforce_auto and can_use_endpoint_cache:
        cache_set('admin-users-online-snapshot', 10, payload)
    return jsonify(payload)


@admin_bp.route('/dashboard/online-users')
@admin_required
def dashboard_online_users():
    enforce_auto = parse_query_bool(request.args.get('enforce', '1'), default=True)
    if not enforce_auto:
        cached_payload = cache_get('dashboard-online-users-snapshot')
        if isinstance(cached_payload, dict):
            return jsonify(cached_payload)

    users_payload = _build_admin_users_online_payload(enforce_auto)
    try:
        total_online = int(users_payload.get('total_online_detected', 0))
    except Exception:
        total_online = 0

    payload = {
        'ok': True,
        'total_online': total_online,
    }
    if not enforce_auto:
        cache_ttl_seconds = max(10, int(math.ceil(get_online_check_interval_ms() / 1000.0)))
        cache_set('dashboard-online-users-snapshot', cache_ttl_seconds, payload)
    return jsonify(payload)


@admin_bp.route('/servers/<int:server_id>/online-debug')
@admin_required
def server_online_debug(server_id: int):
    server = db.session.get(Server, server_id)
    if not server:
        return jsonify({'ok': False, 'msg': 'Servidor no encontrado.'}), 404

    svc = SSHService(server)
    ok, data, err = svc.debug_online_sources()
    if not ok:
        return jsonify({'ok': False, 'msg': err, 'server_id': server_id}), 400

    return jsonify({
        'ok': True,
        'server_id': server_id,
        'server_name': server.name,
        'sources': data,
    })


@admin_bp.route('/users/create', methods=['POST'])
@admin_required
def create_user():
    username = normalize_vpn_username(request.form.get('username', ''))
    password = request.form.get('password', '')
    package_code = request.form.get('package', '1m')
    limit = request.form.get('limit', 1, type=int) or 1
    reseller_id = request.form.get('reseller_id', type=int)
    server_id = request.form.get('server_id', type=int)
    create_as_admin = request.form.get('create_as_admin') in {'1', 'true', 'on'}

    if create_as_admin:
        reseller_id = None

    if not username or not password or not server_id:
        return _respond_user_action('admin.users', MSG_REQUIRED_FIELDS, 'danger', ok=False, status_code=400)

    limit = max(1, limit)

    if not VPN_USERNAME_PATTERN.fullmatch(username):
        return _respond_user_action('admin.users', MSG_USERNAME_FORMAT, 'danger', ok=False, status_code=400)

    server = db.session.get(Server, server_id)
    if not server:
        return _respond_user_action('admin.users', 'Servidor inválido.', 'danger', ok=False, status_code=400)

    if reseller_id:
        reseller = db.session.get(Reseller, reseller_id)
        if not reseller or reseller.note == SYSTEM_ADMIN_RESELLER_NOTE:
            return _respond_user_action('admin.users', 'Revendedor inválido.', 'danger', ok=False, status_code=400)
    else:
        reseller = _get_or_create_system_reseller(server_id)

    package = resolve_package(package_code)
    credits_needed = package.get('credits', 0)
    can_charge, charge_msg = _can_charge_credits(reseller, credits_needed)
    if not can_charge:
        return _respond_user_action('admin.users', charge_msg, 'danger', ok=False, status_code=400)

    svc = SSHService(server)
    can_write, guard_msg = guard_server_storage_before_account_write(svc)
    if not can_write:
        return _respond_user_action('admin.users', guard_msg, 'danger', ok=False, status_code=400)

    # Check if demo already exists for this reseller
    if package_code == 'demo_1h':
        existing_demo = VpnUser.query.filter_by(reseller_id=reseller.id, is_active=True).filter(
            VpnUser.username.like('DEMO-%')
        ).first()
        if existing_demo:
            return _respond_user_action(
                'admin.users',
                'Este revendedor ya tiene un demo activo. Solo se permite 1 demo por revendedor.',
                'demo_limit',
                ok=False,
                status_code=400,
            )

    base_username = username
    username = pick_available_username(base_username)
    if not username:
        return _respond_user_action(
            'admin.users',
            f"No hay sufijos disponibles para '{base_username}' en el panel. Prueba con otro nombre base.",
            'danger',
            ok=False,
            status_code=400,
        )

    svc = SSHService(server)
    create_days = package.get('days', 1)
    ok, msg = svc.create_user(username, password, create_days, limit)

    if not ok:
        return _respond_user_action('admin.users', f'Error al crear usuario: {msg}', 'danger', ok=False, status_code=400)

    expiry_dt = datetime.utcnow() + timedelta(days=create_days)
    if package_code == 'demo_1h':
        expiry_dt = datetime.utcnow() + timedelta(hours=DEMO_MAX_HOURS)

    vu = VpnUser(
        username=username,
        password=password,
        connection_limit=limit,
        expiry_date=expiry_dt,
        reseller_id=reseller.id,
        server_id=server_id,
    )

    if package_code == 'demo_1h':
        sched_ok, sched_msg = svc.schedule_demo_lock(username, DEMO_MAX_HOURS)
        if not sched_ok:
            flash(msg_demo_schedule_warning(sched_msg), 'warning')

    if credits_needed > 0 and reseller.note != SYSTEM_ADMIN_RESELLER_NOTE:
        reseller.panel_credits = max(0, (reseller.panel_credits or 0) - credits_needed)
        _log_credit_movement(
            reseller,
            -credits_needed,
            f"Compra paquete {package['label']} para usuario {username} (creado por admin {current_user.username})",
        )

    db.session.add(vu)
    db.session.commit()
    db.session.refresh(vu)
    charged_credits = credits_needed if (credits_needed > 0 and reseller.note != SYSTEM_ADMIN_RESELLER_NOTE) else 0
    success_msg = build_user_create_success_message(
        msg,
        package['label'],
        charged_credits,
        username,
        base_username,
    )
    return _respond_user_action('admin.users', success_msg, 'success', ok=True, user=vu)


@admin_bp.route('/users/create-demo', methods=['POST'])
@admin_required
def create_demo_user():
    limit = request.form.get('limit', 1, type=int) or 1
    reseller_id = request.form.get('reseller_id', type=int)
    server_id = request.form.get('server_id', type=int)
    create_as_admin = request.form.get('create_as_admin') in {'1', 'true', 'on'}

    if create_as_admin:
        reseller_id = None

    if not server_id:
        return _respond_user_action('admin.users', 'Debes seleccionar un servidor para crear un demo.', 'danger', ok=False, status_code=400)

    limit = max(1, limit)

    server = db.session.get(Server, server_id)
    if not server:
        return _respond_user_action('admin.users', 'Servidor inválido.', 'danger', ok=False, status_code=400)

    if reseller_id:
        reseller = db.session.get(Reseller, reseller_id)
        if not reseller or reseller.note == SYSTEM_ADMIN_RESELLER_NOTE:
            return _respond_user_action('admin.users', 'Revendedor inválido.', 'danger', ok=False, status_code=400)
    else:
        reseller = _get_or_create_system_reseller(server_id)

    svc = SSHService(server)
    can_write, guard_msg = guard_server_storage_before_account_write(svc)
    if not can_write:
        return _respond_user_action('admin.users', guard_msg, 'danger', ok=False, status_code=400)

    # Check if demo already exists for this reseller
    existing_demo = VpnUser.query.filter_by(reseller_id=reseller.id, is_active=True).filter(
        VpnUser.username.like('DEMO-%')
    ).first()
    if existing_demo:
        return _respond_user_action(
            'admin.users',
            'Este revendedor ya tiene un demo activo. Solo se permite 1 demo por revendedor.',
            'demo_limit',
            ok=False,
            status_code=400,
        )

    existing_usernames = load_active_usernames_upper()

    created, username, password, msg = provision_demo_user(
        svc,
        existing_usernames,
        limit,
    )
    if not created and msg:
        return _respond_user_action('admin.users', msg_demo_create_failed(msg), 'danger', ok=False, status_code=400)

    if not created:
        return _respond_user_action('admin.users', MSG_DEMO_NAME_EXHAUSTED, 'danger', ok=False, status_code=400)

    vu = VpnUser(
        username=username,
        password=password,
        connection_limit=limit,
        expiry_date=datetime.utcnow() + timedelta(hours=DEMO_MAX_HOURS),
        reseller_id=reseller.id,
        server_id=server_id,
    )
    db.session.add(vu)
    db.session.commit()
    db.session.refresh(vu)

    sched_ok, sched_msg = svc.schedule_demo_lock(username, DEMO_MAX_HOURS)
    owner_label = 'Admin' if reseller.note == SYSTEM_ADMIN_RESELLER_NOTE else reseller.username
    if not sched_ok:
        flash(msg_demo_schedule_warning(sched_msg), 'warning')
    return _respond_admin_users_action(
        f"Demo creado: usuario '{username}' | clave '{password}' | {DEMO_MAX_HOURS} hora(s) | propietario: {owner_label}.",
        'success',
        ok=True,
        user=vu,
    )


@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id: int):
    u = db.session.get(VpnUser, user_id)
    if not u:
        return _respond_admin_user_not_found()

    svc = SSHService(u.server)
    can_write, guard_msg = guard_server_storage_before_account_write(svc)
    if not can_write:
        return _respond_admin_users_action(guard_msg, 'danger', ok=False, user=u, status_code=400)

    ok, msg = svc.delete_user(u.username)
    if ok:
        u.is_active = False
        db.session.commit()
        return _respond_admin_users_action(f"Usuario '{u.username}' eliminado del servidor.", 'success', ok=True, user=u)

    return _respond_admin_users_action(
        f"Error al eliminar del servidor: {(msg or '').rstrip(' .')}. El usuario sigue activo.",
        'danger',
        ok=False,
        user=u,
        status_code=400,
    )


@admin_bp.route('/users/<int:user_id>/renew', methods=['POST'])
@admin_required
def renew_user(user_id: int):
    u = db.session.get(VpnUser, user_id)
    if not u:
        return _respond_admin_user_not_found()

    if not u.is_active:
        return _respond_admin_users_action('No es posible renovar un usuario inactivo.', 'danger', ok=False, status_code=400)

    if u.username.startswith('DEMO-'):
        return _respond_admin_users_action('Los usuarios demo no se pueden renovar.', 'danger', ok=False, status_code=400)

    package_code = request.form.get('package', '1m')
    if package_code == 'demo_1h':
        return _respond_admin_users_action('No se permite renovar con paquete Demo 1 hora.', 'danger', ok=False, status_code=400)

    package = resolve_package(package_code)
    credits_needed = package.get('credits', 0)

    reseller = u.reseller
    can_charge, charge_msg = _can_charge_credits(reseller, credits_needed)
    if not can_charge:
        return _respond_admin_users_action(charge_msg, 'danger', ok=False, status_code=400)

    new_expiry, days_from_now = compute_renewal_dates(u.expiry_date, package.get('days', 30))

    svc = SSHService(u.server)
    ok, msg = svc.change_expiry(u.username, days_from_now)
    if not ok:
        return _respond_admin_users_action(f'Error al renovar usuario en servidor: {msg}', 'danger', ok=False, status_code=400)

    u.expiry_date = new_expiry

    if credits_needed > 0 and reseller.note != SYSTEM_ADMIN_RESELLER_NOTE:
        reseller.panel_credits = max(0, (reseller.panel_credits or 0) - credits_needed)
        _log_credit_movement(
            reseller,
            -credits_needed,
            f"Renovacion de paquete {package['label']} para usuario {u.username} (renovado por admin {current_user.username})",
        )

    db.session.commit()
    return _respond_admin_users_action(
        f"Usuario '{u.username}' renovado hasta {new_expiry.strftime('%d/%m/%Y %H:%M')}. Paquete: {package['label']}",
        'success',
        ok=True,
        user=u,
    )


@admin_bp.route('/users/<int:user_id>/block', methods=['POST'])
@admin_required
def block_user(user_id: int):
    u = db.session.get(VpnUser, user_id)
    if not u:
        return _respond_admin_user_not_found()

    svc = SSHService(u.server)
    can_write, guard_msg = guard_server_storage_before_account_write(svc)
    if not can_write:
        return _respond_admin_users_action(guard_msg, 'danger', ok=False, user=u, status_code=400)

    ok, msg = apply_user_block_state(u, True, svc, db.session)
    if ok:
        return _respond_admin_users_action(msg, 'success', ok=True, user=u)
    return _respond_admin_users_action(
        compose_action_error('bloquear usuario', msg),
        'danger',
        ok=False,
        user=u,
        status_code=400,
    )


@admin_bp.route('/users/<int:user_id>/unblock', methods=['POST'])
@admin_required
def unblock_user(user_id: int):
    u = db.session.get(VpnUser, user_id)
    if not u:
        return _respond_admin_user_not_found()

    svc = SSHService(u.server)
    ok, msg = apply_user_block_state(u, False, svc, db.session)
    if ok:
        ok_trim, trim_msg = enforce_user_connection_limit(u, svc)
        if ok_trim:
            return _respond_admin_users_action(f"{msg} | {trim_msg}", 'success', ok=True, user=u)
        return _respond_admin_users_action(
            f"{msg} | Aviso: no se pudo normalizar sesiones: {trim_msg}",
            'warning',
            ok=True,
            user=u,
        )
    return _respond_admin_users_action(
        compose_action_error('desbloquear usuario', msg),
        'danger',
        ok=False,
        user=u,
        status_code=400,
    )


@admin_bp.route('/users/<int:user_id>/checkuser-clear', methods=['POST'])
@admin_required
def checkuser_clear_user(user_id: int):
    u = db.session.get(VpnUser, user_id)
    if not u:
        return _respond_admin_user_not_found()

    svc = SSHService(u.server)
    ok, msg = svc.checkuser_clear_user(u.username)
    if ok:
        return _respond_admin_users_action(msg, 'success', ok=True, user=u)
    return _respond_admin_users_action(
        compose_action_error('limpiar CheckUser', msg),
        'danger',
        ok=False,
        user=u,
        status_code=400,
    )


@admin_bp.route('/users/<int:user_id>/diagnostics', methods=['GET'])
@admin_required
def user_diagnostics(user_id: int):
    u = db.session.get(VpnUser, user_id)
    if not u:
        return jsonify({'ok': False, 'message': 'Usuario no encontrado.'}), 404

    svc = SSHService(u.server)
    ok, details = svc.inspect_user_state(u.username)
    if not ok:
        return jsonify({'ok': False, 'message': details.get('error', 'No se pudo diagnosticar'), 'details': details}), 400

    return jsonify({'ok': True, 'user_id': int(u.id), 'username': u.username, 'details': details}), 200


# ──────────────────────────────────────────────────────────
# Change password
# ──────────────────────────────────────────────────────────

@admin_bp.route('/users/<int:user_id>/password', methods=['POST'])
@admin_required
def change_password(user_id: int):
    u = db.session.get(VpnUser, user_id)
    if not u:
        return _respond_admin_user_not_found()

    new_password = request.form.get('password', '')
    svc = SSHService(u.server)
    ok, msg = apply_user_password_change(u, new_password, svc, db.session)
    if ok:
        return _respond_admin_users_action(msg, 'success', ok=True, user=u)
    return _respond_admin_users_action(f'Error: {msg}', 'danger', ok=False, user=u, status_code=400)


# ──────────────────────────────────────────────────────────
# Change limit
# ──────────────────────────────────────────────────────────

@admin_bp.route('/users/<int:user_id>/limit', methods=['POST'])
@admin_required
def change_limit(user_id: int):
    u = db.session.get(VpnUser, user_id)
    if not u:
        return _respond_admin_user_not_found()

    new_limit = request.form.get('limit', type=int)
    if not new_limit or new_limit < 1:
        return _respond_admin_users_action('Límite inválido.', 'danger', ok=False, status_code=400)

    svc = SSHService(u.server)
    ok, msg = apply_user_limit_change(u, new_limit, svc, db.session)
    if ok:
        return _respond_admin_users_action(msg, 'success', ok=True, user=u)
    return _respond_admin_users_action(f'Error: {msg}', 'danger', ok=False, user=u, status_code=400)


@admin_bp.route('/users/<int:user_id>/move-server', methods=['POST'])
@admin_required
def move_user_server(user_id: int):
    u = db.session.get(VpnUser, user_id)
    if not u or not u.is_active:
        return _respond_admin_users_action('Usuario no encontrado o inactivo.', 'danger', ok=False, status_code=404)

    target_server_id = request.form.get('target_server_id', type=int)
    if not target_server_id:
        return _respond_admin_users_action('Debes seleccionar un servidor destino.', 'danger', ok=False, status_code=400)

    if int(target_server_id) == int(u.server_id):
        return _respond_admin_users_action('El usuario ya pertenece a ese servidor.', 'warning', ok=False, status_code=400)

    source_server = u.server
    target_server = db.session.get(Server, target_server_id)
    if not target_server or not target_server.is_active:
        return _respond_admin_users_action('Servidor destino inválido o inactivo.', 'danger', ok=False, status_code=400)

    conflict = (
        VpnUser.query
        .filter(VpnUser.is_active.is_(True))
        .filter(func.upper(VpnUser.username) == (u.username or '').strip().upper())
        .filter(VpnUser.server_id == target_server_id)
        .filter(VpnUser.id != u.id)
        .first()
    )
    if conflict:
        return _respond_admin_users_action(
            (
                f"No se pudo mover '{u.username}': en el servidor destino ya existe "
                'un usuario activo con el mismo nombre.'
            ),
            'danger',
            ok=False,
            status_code=400,
        )

    password = (u.password or '').strip()
    if not password:
        password = generate_demo_password(12)
        u.password = password

    now_utc = datetime.utcnow()
    expiry_dt = u.expiry_date or (now_utc + timedelta(days=1))
    create_days = max(1, int(math.ceil((expiry_dt - now_utc).total_seconds() / 86400.0)))
    limit = max(1, int(u.connection_limit or 1))

    target_svc = SSHService(target_server)
    ok_create, msg_create = target_svc.create_user(u.username, password, create_days, limit)
    if not ok_create:
        return _respond_admin_users_action(
            f"No se pudo crear el usuario en '{target_server.name}': {msg_create}",
            'danger',
            ok=False,
            status_code=400,
        )

    ok_expiry, msg_expiry = target_svc.set_expiry_date(u.username, expiry_dt)
    if not ok_expiry:
        target_svc.delete_user(u.username)
        return _respond_admin_users_action(
            f"No se pudo ajustar expiración en '{target_server.name}': {msg_expiry}",
            'danger',
            ok=False,
            status_code=400,
        )

    if u.is_blocked:
        ok_state, msg_state = target_svc.block_user(u.username)
    else:
        ok_state, msg_state = target_svc.unblock_user(u.username)

    if not ok_state:
        target_svc.delete_user(u.username)
        return _respond_admin_users_action(
            f"No se pudo aplicar estado en '{target_server.name}': {msg_state}",
            'danger',
            ok=False,
            status_code=400,
        )

    source_svc = SSHService(source_server)
    ok_delete_src, msg_delete_src = source_svc.delete_user(u.username)

    if not ok_delete_src:
        return _respond_admin_users_action(
            f"No se pudo eliminar del servidor origen '{source_server.name}': {msg_delete_src}. Usuario no fue transferido.",
            'danger',
            ok=False,
            status_code=400,
        )

    ownership_note = ''
    if u.reseller and u.reseller.note == SYSTEM_ADMIN_RESELLER_NOTE:
        target_owner = _get_or_create_system_reseller(target_server_id)
        u.reseller_id = target_owner.id
    elif u.reseller and int(u.reseller.server_id or 0) != int(target_server_id):
        target_owner = _get_or_create_system_reseller(target_server_id)
        previous_owner = u.reseller.username
        u.reseller_id = target_owner.id
        ownership_note = f" | Propietario ajustado: {previous_owner} -> Admin"

    u.server_id = target_server_id
    db.session.commit()
    db.session.refresh(u)

    return _respond_admin_users_action(
        (
            f"Usuario '{u.username}' movido de '{source_server.name}' a '{target_server.name}'."
            f"{ownership_note}"
        ),
        'success',
        ok=True,
        user=u,
    )


# ──────────────────────────────────────────────────────────
# Backup / Restore
# ──────────────────────────────────────────────────────────

@admin_bp.route('/backup/create', methods=['POST'])
@admin_required
def create_backup():
    try:
        db_path = _sqlite_db_path()
    except ValueError as ex:
        flash(str(ex), 'danger')
        return redirect(url_for('admin.dashboard'))

    if not os.path.isfile(db_path):
        flash('No se encontró la base de datos para generar la copia.', 'danger')
        return redirect(url_for('admin.dashboard'))

    key_path = os.path.join(current_app.instance_path, '.enc_key')

    # Snapshot consistente de SQLite
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as temp_db:
        snapshot_db = temp_db.name

    try:
        src = sqlite3.connect(db_path)
        dst = sqlite3.connect(snapshot_db)
        src.backup(dst)
        dst.close()
        src.close()

        backup_stream = io.BytesIO()
        now_panel = datetime.now(_panel_tzinfo())
        created_at = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        filename = f"vpnpro-backup-{now_panel.strftime('%Y%m%d-%H%M%S')}.zip"
        backup_file_path = os.path.join(_backups_dir(), filename)
        metadata = {
            'app': 'VPNPro Web Panel',
            'created_at_utc': created_at,
            'created_at_panel': now_panel.isoformat(),
            'panel_timezone': _get_panel_timezone(),
            'format': 'vpnpro-backup-v1',
            'files': ['vpnpro.db'] + (['.enc_key'] if os.path.isfile(key_path) else []),
        }

        with zipfile.ZipFile(backup_stream, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(snapshot_db, arcname='vpnpro.db')
            if os.path.isfile(key_path):
                zf.write(key_path, arcname='.enc_key')
            zf.writestr('metadata.json', json.dumps(metadata, ensure_ascii=True, indent=2))

        with open(backup_file_path, 'wb') as fh:
            fh.write(backup_stream.getvalue())

        removed_age, removed_count = _prune_backups()
        if removed_age or removed_count:
            current_app.logger.info(
                'Retencion de backups aplicada: %s por antiguedad, %s por cantidad.',
                removed_age,
                removed_count,
            )

        backup_stream.seek(0)
        return send_file(
            backup_stream,
            as_attachment=True,
            download_name=filename,
            mimetype='application/zip',
        )
    finally:
        if os.path.exists(snapshot_db):
            os.remove(snapshot_db)


@admin_bp.route('/backup/restore', methods=['POST'])
@admin_required
def restore_backup():
    uploaded = request.files.get('backup_file')
    if not uploaded or not uploaded.filename:
        flash('Selecciona un archivo de copia (.zip).', 'danger')
        return redirect(url_for('admin.dashboard'))

    if not uploaded.filename.lower().endswith('.zip'):
        flash('Formato inválido. Debe ser un archivo .zip generado por el panel.', 'danger')
        return redirect(url_for('admin.dashboard'))

    try:
        db_path = _sqlite_db_path()
    except ValueError as ex:
        flash(str(ex), 'danger')
        return redirect(url_for('admin.dashboard'))

    key_path = os.path.join(current_app.instance_path, '.enc_key')
    os.makedirs(current_app.instance_path, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        zip_path = os.path.join(tmpdir, 'restore.zip')
        db_tmp = os.path.join(tmpdir, 'vpnpro.db')
        key_tmp = os.path.join(tmpdir, '.enc_key')
        uploaded.save(zip_path)

        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                names = zf.namelist()
                db_member = _find_zip_member(names, 'vpnpro.db')
                if not db_member:
                    flash('El ZIP no contiene vpnpro.db. Copia inválida.', 'danger')
                    return redirect(url_for('admin.dashboard'))

                with zf.open(db_member, 'r') as src, open(db_tmp, 'wb') as dst:
                    shutil.copyfileobj(src, dst)

                key_member = _find_zip_member(names, '.enc_key')
                if key_member:
                    with zf.open(key_member, 'r') as src, open(key_tmp, 'wb') as dst:
                        shutil.copyfileobj(src, dst)

            # Validar integridad de SQLite antes de reemplazar
            conn = sqlite3.connect(db_tmp)
            integrity = conn.execute('PRAGMA integrity_check;').fetchone()[0]
            conn.close()
            if integrity.lower() != 'ok':
                flash('La copia está dañada (integrity_check falló).', 'danger')
                return redirect(url_for('admin.dashboard'))

            restore_lock = current_app.extensions['db_restore_lock']
            with restore_lock:
                current_app.logger.info('[RESTORE] Iniciando reemplazo de base SQLite desde backup.')
                db.session.remove()
                db.engine.dispose()

                db_backup = db_path + '.pre-restore.bak'
                key_backup = key_path + '.pre-restore.bak'
                if os.path.isfile(db_path):
                    shutil.copy2(db_path, db_backup)
                if os.path.isfile(key_path):
                    shutil.copy2(key_path, key_backup)
                _prune_restore_artifacts()

                _remove_sqlite_sidecars(db_path)
                shutil.copy2(db_tmp, db_path)
                _remove_sqlite_sidecars(db_path)
                if os.path.isfile(key_tmp):
                    shutil.copy2(key_tmp, key_path)
                    with open(key_path, 'rb') as fh:
                        current_app.config['ENCRYPTION_KEY'] = fh.read().strip()

            current_app.extensions['restore_guard_until'] = time.time() + _RESTORE_GUARD_SECONDS
            current_app.logger.info(
                '[RESTORE-GUARD] Ventana de protección activada por %s segundo(s).',
                _RESTORE_GUARD_SECONDS,
            )

            flash('Copia restaurada correctamente. Se recomienda reiniciar el servicio del panel.', 'success')
            return redirect(url_for('admin.dashboard'))

        except zipfile.BadZipFile:
            flash('El archivo subido no es un ZIP válido.', 'danger')
            return redirect(url_for('admin.dashboard'))
        except Exception as ex:
            flash(f'Error al restaurar copia: {ex}', 'danger')
            return redirect(url_for('admin.dashboard'))


@admin_bp.route('/backup/download/<path:filename>', methods=['GET'])
@admin_required
def download_backup(filename: str):
    full_path = _safe_backup_file(filename)
    if not full_path:
        flash('Archivo de copia no encontrado.', 'danger')
        return redirect(url_for('admin.dashboard'))
    return send_file(full_path, as_attachment=True, download_name=os.path.basename(full_path))


@admin_bp.route('/backup/delete/<path:filename>', methods=['POST'])
@admin_required
def delete_backup(filename: str):
    full_path = _safe_backup_file(filename)
    if not full_path:
        flash('Archivo de copia no encontrado.', 'danger')
        return redirect(url_for('admin.dashboard'))

    os.remove(full_path)
    flash('Copia eliminada del historial.', 'success')
    return redirect(url_for('admin.dashboard'))


@admin_bp.route('/panel/restart', methods=['POST'])
@admin_required
def restart_panel_service():
    cmd = 'sleep 1; systemctl restart vpnpro-web.service >/dev/null 2>&1'
    try:
        subprocess.Popen(['sh', '-c', cmd])
        flash('Reinicio del panel solicitado. Espera unos segundos y recarga la página.', 'success')
    except Exception as ex:
        flash(f'No se pudo solicitar el reinicio del panel: {ex}', 'danger')
    return redirect(url_for('admin.dashboard'))
