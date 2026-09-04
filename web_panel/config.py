import os
import secrets
from cryptography.fernet import Fernet

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _resolve_instance_dir() -> str:
    for env_name in ('PANEL_DATA_DIR', 'VPNPRO_DATA_DIR'):
        value = (os.environ.get(env_name) or '').strip()
        if value:
            return os.path.abspath(value)

    linux_default = '/var/lib/vpnpro-web'
    linux_parent = os.path.dirname(linux_default)
    if os.name != 'nt' and (os.path.isdir(linux_default) or os.access(linux_parent, os.W_OK)):
        return linux_default

    return os.path.join(_BASE_DIR, 'instance')


_INSTANCE_DIR = _resolve_instance_dir()
_KEY_FILE = os.path.join(_INSTANCE_DIR, '.enc_key')
_SECRET_KEY_FILE = os.path.join(_INSTANCE_DIR, '.secret_key')


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {'1', 'true', 'yes', 'on', 'si'}


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        parsed = int(value.strip())
    except (TypeError, ValueError):
        return default
    return max(minimum, parsed)


def _env_port(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        port = int(value.strip())
    except (TypeError, ValueError):
        return default
    if 1 <= port <= 65535:
        return port
    return default


def _env_port_list(name: str, default: str) -> list[int]:
    raw = os.environ.get(name, default)
    values: list[int] = []
    for token in raw.split(','):
        token = token.strip()
        if not token:
            continue
        try:
            port = int(token)
        except ValueError:
            continue
        if 1 <= port <= 65535 and port not in values:
            values.append(port)
    return values


def _load_or_create_encryption_key() -> bytes:
    os.makedirs(_INSTANCE_DIR, exist_ok=True)
    if os.path.isfile(_KEY_FILE):
        with open(_KEY_FILE, 'rb') as fh:
            return fh.read().strip()
    key = Fernet.generate_key()
    with open(_KEY_FILE, 'wb') as fh:
        fh.write(key)
    if os.name != 'nt':
        os.chmod(_KEY_FILE, 0o600)
    return key


def _load_or_create_secret_key() -> str:
    os.makedirs(_INSTANCE_DIR, exist_ok=True)
    if os.path.isfile(_SECRET_KEY_FILE):
        with open(_SECRET_KEY_FILE, 'r') as fh:
            value = fh.read().strip()
        if value:
            return value
    key = secrets.token_hex(32)
    with open(_SECRET_KEY_FILE, 'w') as fh:
        fh.write(key)
    if os.name != 'nt':
        os.chmod(_SECRET_KEY_FILE, 0o600)
    return key


class Config:
    INSTANCE_DIR: str = _INSTANCE_DIR
    SECRET_KEY: str = os.environ.get('SECRET_KEY') or _load_or_create_secret_key()
    SQLALCHEMY_DATABASE_URI: str = (
        os.environ.get('DATABASE_URL') or
        f"sqlite:///{os.path.join(INSTANCE_DIR, 'vpnpro.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # SQLite: allow multi-thread access and wait up to 30 s when DB is locked
    # (background workers hold write locks for several seconds).
    SQLALCHEMY_ENGINE_OPTIONS: dict = {
        'connect_args': {
            'check_same_thread': False,
            'timeout': 30,
        }
    }
    WTF_CSRF_ENABLED = True
    AUTO_SYNC_ENABLED = _env_bool('AUTO_SYNC_ENABLED', True)
    AUTO_SYNC_INTERVAL_MINUTES = _env_int('AUTO_SYNC_INTERVAL_MINUTES', 30, minimum=1)
    AUTO_LIMITER_ENABLED = _env_bool('AUTO_LIMITER_ENABLED', True)
    AUTO_LIMITER_INTERVAL_SECONDS = _env_int('AUTO_LIMITER_INTERVAL_SECONDS', 10, minimum=2)
    AUTO_TRIM_CONFIRMATION_SECONDS = _env_int(
        'AUTO_TRIM_CONFIRMATION_SECONDS',
        max(30, AUTO_LIMITER_INTERVAL_SECONDS * 2),
        minimum=5,
    )
    AUTO_TRIM_FIRST_STRIKE_LIMIT_ONE = _env_bool('AUTO_TRIM_FIRST_STRIKE_LIMIT_ONE', True)
    AUTO_TRIM_USER_COOLDOWN_SECONDS = _env_int(
        'AUTO_TRIM_USER_COOLDOWN_SECONDS',
        max(20, AUTO_LIMITER_INTERVAL_SECONDS * 2),
        minimum=5,
    )
    AUTO_DISK_HOUSEKEEPING_ENABLED = _env_bool('AUTO_DISK_HOUSEKEEPING_ENABLED', True)
    AUTO_DISK_HOUSEKEEPING_INTERVAL_MINUTES = _env_int('AUTO_DISK_HOUSEKEEPING_INTERVAL_MINUTES', 30, minimum=5)
    AUTO_DISK_HOUSEKEEPING_ON_GUARD = _env_bool('AUTO_DISK_HOUSEKEEPING_ON_GUARD', True)
    DISK_HOUSEKEEPING_TRIGGER_PERCENT = _env_int('DISK_HOUSEKEEPING_TRIGGER_PERCENT', 88, minimum=50)
    DISK_HOUSEKEEPING_JOURNAL_MAX_MB = _env_int('DISK_HOUSEKEEPING_JOURNAL_MAX_MB', 200, minimum=50)
    DISK_HOUSEKEEPING_TMP_MAX_AGE_DAYS = _env_int('DISK_HOUSEKEEPING_TMP_MAX_AGE_DAYS', 3, minimum=1)
    ROOT_DISK_CRITICAL_PERCENT = _env_int('ROOT_DISK_CRITICAL_PERCENT', 98, minimum=80)
    WEB_PANEL_PORT = _env_port('WEB_PANEL_PORT', 80)
    AUTO_OPEN_PORTS_ON_FIRST_CONNECT = _env_bool(
        'AUTO_OPEN_PORTS_ON_FIRST_CONNECT',
        _env_bool('AUTO_OPEN_PORTS_ON_SERVER_CREATE', True),
    )
    AUTO_OPEN_TCP_PORTS = _env_port_list('AUTO_OPEN_TCP_PORTS', '80,443,8080')
    AUTO_OPEN_UDP_PORTS = _env_port_list('AUTO_OPEN_UDP_PORTS', '')
    ONLINE_CHECK_INTERVAL_MS = _env_int('ONLINE_CHECK_INTERVAL_MS', 5000, minimum=1000)
    ENCRYPTION_KEY: bytes = (
        os.environ.get('ENCRYPTION_KEY', '').encode() or
        _load_or_create_encryption_key()
    )
