from __future__ import annotations

from datetime import datetime, timedelta
from functools import wraps
from sqlalchemy import func
from sqlalchemy.orm import load_only

from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from flask_login import login_required, current_user, logout_user

from models import db, Reseller, VpnUser, CreditMovement
from routes.messages import (
    MSG_DEMO_ALREADY_EXISTS,
    MSG_DEMO_NAME_EXHAUSTED,
    MSG_REQUIRED_FIELDS,
    MSG_USERNAME_FORMAT,
    msg_credits_insufficient,
    msg_demo_create_failed,
    msg_demo_schedule_warning,
)
from services.ssh_service import SSHService
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
    get_cached_online_snapshot,
    get_online_check_interval_ms,
    load_active_usernames_upper,
    normalize_vpn_username,
    parse_query_bool,
    pick_available_username,
    provision_demo_user,
    respond_user_action,
    resolve_package,
    serialize_user_for_ui,
)

reseller_bp = Blueprint('reseller', __name__)
DEMO_MIN_CREDITS = 5


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
        user_serializer=serialize_user_for_ui,
    )


def _respond_reseller_users_action(
    message: str,
    category: str,
    *,
    ok: bool,
    user: VpnUser | None = None,
    status_code: int = 200,
):
    return _respond_user_action(
        'reseller.users',
        message,
        category,
        ok=ok,
        user=user,
        status_code=status_code,
    )


def _respond_reseller_user_not_found():
    return _respond_reseller_users_action('Usuario no encontrado.', 'danger', ok=False, status_code=404)


def _get_reseller_owned_user(user_id: int) -> VpnUser | None:
    reseller = current_user
    user = db.session.get(VpnUser, user_id)
    if not user or int(user.reseller_id or 0) != int(reseller.id):
        return None
    return user


def _reseller_limit_denied_message(limit: int, max_connections: int, *, demo: bool = False) -> str:
    target = 'demo' if demo else 'usuario'
    return (
        f'No, no puedes crear este {target} con {limit} conexión(es). '
        f'El administrador te permite hasta {max_connections} conexión(es) por usuario.'
    )


def _build_reseller_renew_success_message(
    username: str,
    new_expiry: datetime,
    package_label: str,
    credits_needed: int,
) -> str:
    message = (
        f"Usuario '{username}' renovado hasta {new_expiry.strftime('%d/%m/%Y %H:%M')}. "
        f'Paquete: {package_label}'
    )
    if credits_needed > 0:
        message += f' | Creditos cobrados: {credits_needed}'
    return message


def _validate_demo_creation_requirements(reseller: Reseller) -> tuple[bool, str, str]:
    if (reseller.panel_credits or 0) < DEMO_MIN_CREDITS:
        return (
            False,
            f'Para crear demos necesitas al menos {DEMO_MIN_CREDITS} créditos disponibles. Tienes {reseller.panel_credits or 0}.',
            'danger',
        )

    existing_demo = (
        VpnUser.query
        .filter_by(reseller_id=reseller.id, is_active=True)
        .filter(VpnUser.username.like('DEMO-%'))
        .first()
    )
    if existing_demo:
        return False, MSG_DEMO_ALREADY_EXISTS, 'demo_limit'

    return True, '', ''


def _get_cached_reseller_total_count(reseller_id: int) -> int:
    count_cache_key = f'reseller-dashboard-total-count:{int(reseller_id)}'
    cached_total = cache_get(count_cache_key)
    if isinstance(cached_total, int):
        return int(cached_total)

    total_users = VpnUser.query.filter_by(reseller_id=reseller_id, is_active=True).count()
    cache_set(count_cache_key, 10, int(total_users))
    return int(total_users)


def reseller_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not isinstance(current_user, Reseller):
            flash('Acceso restringido a revendedores.', 'danger')
            return redirect(url_for('auth.login'))
        if not current_user.is_active:
            flash('Tu cuenta está desactivada.', 'danger')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return login_required(decorated)


# ──────────────────────────────────────────────────────────
# Dashboard
# ──────────────────────────────────────────────────────────

@reseller_bp.route('/')
@reseller_required
def dashboard():
    r: Reseller = current_user
    total_count = _get_cached_reseller_total_count(r.id)

    credit_logs = (
        CreditMovement.query
        .options(
            load_only(
                CreditMovement.id,
                CreditMovement.delta,
                CreditMovement.balance_after,
                CreditMovement.reason,
                CreditMovement.created_at,
            )
        )
        .filter_by(reseller_id=r.id)
        .order_by(CreditMovement.created_at.desc())
        .limit(12)
        .all()
    )

    return render_template(
        'reseller/dashboard.html',
        reseller=r,
            server=r.server,
        total_count=total_count,
        credit_logs=credit_logs,
    )


@reseller_bp.route('/dashboard/summary')
@reseller_required
def dashboard_summary():
    r: Reseller = current_user
    cache_key = f'reseller-dashboard-summary:{int(r.id)}'
    cached_payload = cache_get(cache_key)
    if isinstance(cached_payload, dict):
        return jsonify(cached_payload)

    reseller_row = (
        Reseller.query
        .options(load_only(Reseller.id, Reseller.max_connections, Reseller.panel_credits))
        .filter_by(id=r.id)
        .first()
    )

    total_users = _get_cached_reseller_total_count(r.id)

    payload = {
        'ok': True,
        'total_users': int(total_users),
        'panel_credits': int((reseller_row.panel_credits if reseller_row else 0) or 0),
        'max_connections': int((reseller_row.max_connections if reseller_row else 0) or 0),
    }
    cache_set(cache_key, 10, payload)
    return jsonify(payload)


@reseller_bp.route('/account', methods=['POST'])
@reseller_required
def update_account():
    r: Reseller = current_user
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')

    if not r.check_password(current_password):
        flash('La contraseña actual no es correcta.', 'danger')
        return redirect(url_for('reseller.dashboard'))

    changed = False
    password_changed = False

    if new_password:
        if len(new_password) < 6:
            flash('La nueva contraseña debe tener al menos 6 caracteres.', 'danger')
            return redirect(url_for('reseller.dashboard'))
        if new_password != confirm_password:
            flash('La confirmación de contraseña no coincide.', 'danger')
            return redirect(url_for('reseller.dashboard'))
        r.set_password(new_password)
        password_changed = True
        changed = True

    if not changed:
        flash('No se detectaron cambios para guardar.', 'warning')
        return redirect(url_for('reseller.dashboard'))

    db.session.commit()
    if password_changed:
        logout_user()
        flash('Contraseña actualizada. Inicia sesión nuevamente.', 'success')
        return redirect(url_for('auth.login'))

    flash('Credenciales actualizadas.', 'success')
    return redirect(url_for('reseller.dashboard'))


# ──────────────────────────────────────────────────────────
# VPN Users — list
# ──────────────────────────────────────────────────────────

@reseller_bp.route('/users')
@reseller_required
def users():

    r: Reseller = current_user
    page = request.args.get('page', 1, type=int) or 1
    per_page = request.args.get('per_page', 150, type=int) or 150
    filter_q = (request.args.get('q', '') or '').strip()
    filter_state = (request.args.get('state', '') or '').strip().lower()
    now_utc = datetime.utcnow()
    page = max(1, int(page))
    per_page = max(25, min(400, int(per_page)))

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
                VpnUser.created_at,
                VpnUser.reseller_id,
                VpnUser.server_id,
            )
        )
        .filter_by(reseller_id=r.id, is_active=True)
    )

    if filter_q:
        q_upper = filter_q.upper()
        users_query = users_query.filter(func.upper(VpnUser.username).like(f'%{q_upper}%'))
    if filter_state == 'blocked':
        users_query = users_query.filter(VpnUser.is_blocked.is_(True))
    elif filter_state == 'expired':
        users_query = users_query.filter(VpnUser.expiry_date < now_utc)
    elif filter_state == 'active':
        users_query = users_query.filter(VpnUser.is_blocked.is_(False), VpnUser.expiry_date >= now_utc)

    users_pagination = users_query.order_by(VpnUser.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    return render_template(
        'reseller/users.html',
        reseller=r,
        server=r.server,
        users=list(users_pagination.items),
        page=page,
        per_page=per_page,
        total=users_pagination.total,
        pages=users_pagination.pages,
        has_prev=users_pagination.has_prev,
        has_next=users_pagination.has_next,
        filter_q=filter_q,
        filter_state=filter_state,
        package_options=PACKAGE_OPTIONS,
        online_check_interval_ms=get_online_check_interval_ms(),
    )

# ──────────────────────────────────────────────────────────
# Create user
# ──────────────────────────────────────────────────────────

@reseller_bp.route('/users/create', methods=['POST'])
@reseller_required
def create_user():
    r: Reseller = current_user

    username = normalize_vpn_username(request.form.get('username', ''))
    password = request.form.get('password', '')
    package_code = request.form.get('package', '1m')
    limit = request.form.get('limit', 1, type=int) or 1

    if not username or not password:
        return _respond_reseller_users_action(MSG_REQUIRED_FIELDS, 'danger', ok=False, status_code=400)

    limit = max(1, limit)

    if not VPN_USERNAME_PATTERN.fullmatch(username):
        return _respond_reseller_users_action(MSG_USERNAME_FORMAT, 'danger', ok=False, status_code=400)

    if int(limit) > r.max_connections:
        return _respond_reseller_users_action(
            _reseller_limit_denied_message(limit, r.max_connections),
            'danger',
            ok=False,
            status_code=400,
        )

    base_username = username
    username = pick_available_username(base_username)
    if not username:
        return _respond_reseller_users_action(
            f"No hay sufijos disponibles para '{base_username}' en el panel. Prueba con otro nombre base.",
            'danger',
            ok=False,
            status_code=400,
        )

    package = resolve_package(package_code)
    credits_needed = package.get('credits', 0)
    if package_code == 'demo_1h':
        valid_demo, demo_msg, demo_category = _validate_demo_creation_requirements(r)
        if not valid_demo:
            return _respond_reseller_users_action(demo_msg, demo_category, ok=False, status_code=400)

    svc = SSHService(r.server)
    can_write, guard_msg = guard_server_storage_before_account_write(svc)
    if not can_write:
        return _respond_reseller_users_action(guard_msg, 'danger', ok=False, status_code=400)

    if credits_needed > 0 and (r.panel_credits or 0) < credits_needed:
        return _respond_reseller_users_action(
            msg_credits_insufficient(credits_needed, r.panel_credits or 0),
            'danger',
            ok=False,
            status_code=400,
        )

    create_days = package.get('days', 1)
    ok, msg = svc.create_user(username, password, create_days, limit)

    if not ok:
        return _respond_reseller_users_action(f'Error al crear usuario: {msg}', 'danger', ok=False, status_code=400)

    expiry_dt = datetime.utcnow() + timedelta(days=create_days)
    if package_code == 'demo_1h':
        expiry_dt = datetime.utcnow() + timedelta(hours=DEMO_MAX_HOURS)

    vu = VpnUser(
        username=username,
        password=password,
        connection_limit=limit,
        expiry_date=expiry_dt,
        reseller_id=r.id,
        server_id=r.server_id,
    )

    if package_code == 'demo_1h':
        sched_ok, sched_msg = svc.schedule_demo_lock(username, DEMO_MAX_HOURS)
        if not sched_ok:
            flash(msg_demo_schedule_warning(sched_msg), 'warning')

    if credits_needed > 0:
        r.panel_credits = max(0, (r.panel_credits or 0) - credits_needed)
        db.session.add(
            CreditMovement(
                reseller_id=r.id,
                delta=-credits_needed,
                balance_after=r.panel_credits or 0,
                reason=f"Compra paquete {package['label']} para usuario {username}",
            )
        )

    db.session.add(vu)
    db.session.commit()
    db.session.refresh(vu)
    success_msg = build_user_create_success_message(
        msg,
        package['label'],
        credits_needed if credits_needed > 0 else 0,
        username,
        base_username,
    )
    return _respond_reseller_users_action(success_msg, 'success', ok=True, user=vu)


@reseller_bp.route('/users/create-demo', methods=['POST'])
@reseller_required
def create_demo_user():
    r: Reseller = current_user
    limit = request.form.get('limit', 1, type=int) or 1

    limit = max(1, limit)

    if int(limit) > r.max_connections:
        return _respond_reseller_users_action(
            _reseller_limit_denied_message(limit, r.max_connections, demo=True),
            'danger',
            ok=False,
            status_code=400,
        )

    valid_demo, demo_msg, demo_category = _validate_demo_creation_requirements(r)
    if not valid_demo:
        return _respond_reseller_users_action(demo_msg, demo_category, ok=False, status_code=400)

    svc = SSHService(r.server)
    can_write, guard_msg = guard_server_storage_before_account_write(svc)
    if not can_write:
        return _respond_reseller_users_action(guard_msg, 'danger', ok=False, status_code=400)

    existing_usernames = load_active_usernames_upper()

    created, username, password, msg = provision_demo_user(
        svc,
        existing_usernames,
        limit,
    )
    if not created and msg:
        return _respond_reseller_users_action(msg_demo_create_failed(msg), 'danger', ok=False, status_code=400)

    if not created:
        return _respond_reseller_users_action(MSG_DEMO_NAME_EXHAUSTED, 'danger', ok=False, status_code=400)

    vu = VpnUser(
        username=username,
        password=password,
        connection_limit=limit,
        expiry_date=datetime.utcnow() + timedelta(hours=DEMO_MAX_HOURS),
        reseller_id=r.id,
        server_id=r.server_id,
    )
    db.session.add(vu)
    db.session.commit()
    db.session.refresh(vu)

    sched_ok, sched_msg = svc.schedule_demo_lock(username, DEMO_MAX_HOURS)
    if not sched_ok:
        flash(msg_demo_schedule_warning(sched_msg), 'warning')
    return _respond_reseller_users_action(
        f"Demo creado: usuario '{username}' | clave '{password}' | {DEMO_MAX_HOURS} hora(s).",
        'success',
        ok=True,
        user=vu,
    )


# ──────────────────────────────────────────────────────────
# Delete user
# ──────────────────────────────────────────────────────────

@reseller_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@reseller_required
def delete_user(user_id: int):
    u = _get_reseller_owned_user(user_id)
    if not u:
        return _respond_reseller_user_not_found()

    svc = SSHService(u.server)
    can_write, guard_msg = guard_server_storage_before_account_write(svc)
    if not can_write:
        return _respond_reseller_users_action(guard_msg, 'danger', ok=False, user=u, status_code=400)

    ok, msg = svc.delete_user(u.username)
    if ok:
        u.is_active = False
        db.session.commit()
        return _respond_reseller_users_action(f"Usuario '{u.username}' eliminado.", 'success', ok=True, user=u)

    return _respond_reseller_users_action(
        f"Error en servidor: {(msg or '').rstrip(' .')}. El usuario sigue activo.",
        'warning',
        ok=False,
        user=u,
        status_code=400,
    )


# ──────────────────────────────────────────────────────────
# Change password
# ──────────────────────────────────────────────────────────

@reseller_bp.route('/users/<int:user_id>/password', methods=['POST'])
@reseller_required
def change_password(user_id: int):
    u = _get_reseller_owned_user(user_id)
    if not u:
        return _respond_reseller_user_not_found()

    new_password = request.form.get('password', '')
    svc = SSHService(u.server)
    ok, msg = apply_user_password_change(u, new_password, svc, db.session)
    if ok:
        return _respond_reseller_users_action(msg, 'success', ok=True, user=u)
    return _respond_reseller_users_action(f'Error: {msg}', 'danger', ok=False, user=u, status_code=400)


# ──────────────────────────────────────────────────────────
# Change limit
# ──────────────────────────────────────────────────────────

@reseller_bp.route('/users/<int:user_id>/limit', methods=['POST'])
@reseller_required
def change_limit(user_id: int):
    r: Reseller = current_user
    u = _get_reseller_owned_user(user_id)
    if not u:
        return _respond_reseller_user_not_found()

    new_limit = request.form.get('limit', type=int)
    if not new_limit or new_limit < 1:
        return _respond_reseller_users_action('Límite inválido.', 'danger', ok=False, status_code=400)

    if new_limit > r.max_connections:
        return _respond_reseller_users_action(
            f'No, no puedes aumentar este límite a {new_limit}. El administrador te permite hasta {r.max_connections} conexión(es) por usuario.',
            'danger',
            ok=False,
            status_code=400,
        )

    svc = SSHService(u.server)
    ok, msg = apply_user_limit_change(u, new_limit, svc, db.session)
    if ok:
        return _respond_reseller_users_action(msg, 'success', ok=True, user=u)
    return _respond_reseller_users_action(f'Error: {msg}', 'danger', ok=False, user=u, status_code=400)


# ──────────────────────────────────────────────────────────
# Change expiry
# ──────────────────────────────────────────────────────────

@reseller_bp.route('/users/<int:user_id>/expiry', methods=['POST'])
@reseller_required
def change_expiry(user_id: int):
    r: Reseller = current_user
    u = _get_reseller_owned_user(user_id)
    if not u:
        return _respond_reseller_user_not_found()

    if u.username.startswith('DEMO-'):
        return _respond_reseller_users_action('Los usuarios demo no se pueden renovar.', 'danger', ok=False, status_code=400)

    package_code = request.form.get('package', '1m')
    if package_code == 'demo_1h':
        return _respond_reseller_users_action('No se permite renovar con paquete Demo 1 hora.', 'danger', ok=False, status_code=400)

    package = resolve_package(package_code)
    credits_needed = package.get('credits', 0)

    if credits_needed > 0 and (r.panel_credits or 0) < credits_needed:
        return _respond_reseller_users_action(
            msg_credits_insufficient(credits_needed, r.panel_credits or 0),
            'danger',
            ok=False,
            status_code=400,
        )

    new_expiry, days_from_now = compute_renewal_dates(u.expiry_date, package.get('days', 30))

    svc = SSHService(u.server)
    ok, msg = svc.change_expiry(u.username, days_from_now)
    if ok:
        u.expiry_date = new_expiry
        if credits_needed > 0:
            r.panel_credits = max(0, (r.panel_credits or 0) - credits_needed)
            db.session.add(
                CreditMovement(
                    reseller_id=r.id,
                    delta=-credits_needed,
                    balance_after=r.panel_credits or 0,
                    reason=f"Renovacion paquete {package['label']} para usuario {u.username}",
                )
            )
        db.session.commit()
        return _respond_reseller_users_action(
            _build_reseller_renew_success_message(u.username, new_expiry, package['label'], credits_needed),
            'success',
            ok=True,
            user=u,
        )
    return _respond_reseller_users_action(f'Error al renovar usuario: {msg}', 'danger', ok=False, user=u, status_code=400)


@reseller_bp.route('/users/<int:user_id>/block', methods=['POST'])
@reseller_required
def block_user(user_id: int):
    u = _get_reseller_owned_user(user_id)
    if not u:
        return _respond_reseller_user_not_found()

    svc = SSHService(u.server)
    can_write, guard_msg = guard_server_storage_before_account_write(svc)
    if not can_write:
        return _respond_reseller_users_action(guard_msg, 'danger', ok=False, user=u, status_code=400)

    ok, msg = apply_user_block_state(u, True, svc, db.session)
    if ok:
        return _respond_reseller_users_action(msg, 'success', ok=True, user=u)
    return _respond_reseller_users_action(
        compose_action_error('bloquear usuario', msg),
        'danger',
        ok=False,
        user=u,
        status_code=400,
    )


@reseller_bp.route('/users/<int:user_id>/unblock', methods=['POST'])
@reseller_required
def unblock_user(user_id: int):
    u = _get_reseller_owned_user(user_id)
    if not u:
        return _respond_reseller_user_not_found()

    svc = SSHService(u.server)
    ok, msg = apply_user_block_state(u, False, svc, db.session)
    if ok:
        ok_trim, trim_msg = enforce_user_connection_limit(u, svc)
        if ok_trim:
            return _respond_reseller_users_action(f"{msg} | {trim_msg}", 'success', ok=True, user=u)
        return _respond_reseller_users_action(
            f"{msg} | Aviso: no se pudo normalizar sesiones: {trim_msg}",
            'warning',
            ok=True,
            user=u,
        )
    return _respond_reseller_users_action(
        compose_action_error('desbloquear usuario', msg),
        'danger',
        ok=False,
        user=u,
        status_code=400,
    )


@reseller_bp.route('/users/<int:user_id>/checkuser-clear', methods=['POST'])
@reseller_required
def checkuser_clear_user(user_id: int):
    u = _get_reseller_owned_user(user_id)
    if not u:
        return _respond_reseller_user_not_found()

    svc = SSHService(u.server)
    ok, msg = svc.checkuser_clear_user(u.username)
    if ok:
        return _respond_reseller_users_action(msg, 'success', ok=True, user=u)
    return _respond_reseller_users_action(
        compose_action_error('limpiar CheckUser', msg),
        'danger',
        ok=False,
        user=u,
        status_code=400,
    )


@reseller_bp.route('/users/<int:user_id>/diagnostics', methods=['GET'])
@reseller_required
def user_diagnostics(user_id: int):
    u = _get_reseller_owned_user(user_id)
    if not u:
        return jsonify({'ok': False, 'message': 'Usuario no encontrado.'}), 404

    svc = SSHService(u.server)
    ok, details = svc.inspect_user_state(u.username)
    if not ok:
        return jsonify({'ok': False, 'message': details.get('error', 'No se pudo diagnosticar'), 'details': details}), 400

    return jsonify({'ok': True, 'user_id': int(u.id), 'username': u.username, 'details': details}), 200


# ──────────────────────────────────────────────────────────
# Online users (AJAX)
# ──────────────────────────────────────────────────────────

@reseller_bp.route('/users/online')
@reseller_required
def online_users():
    r: Reseller = current_user
    enforce_auto = parse_query_bool(request.args.get('enforce', '1'), default=True)
    prefer_fresh_snapshot = parse_query_bool(request.args.get('fresh', '0'), default=False)
    requested_user_ids = _parse_requested_user_ids()
    can_use_endpoint_cache = (not requested_user_ids) and (not prefer_fresh_snapshot)
    if not enforce_auto and can_use_endpoint_cache:
        cache_key = f'reseller-online-snapshot:{int(r.id)}'
        cached_payload = cache_get(cache_key)
        if isinstance(cached_payload, dict):
            return jsonify(cached_payload)

    user_rows_query = (
        db.session.query(
            VpnUser.id,
            VpnUser.username,
            VpnUser.connection_limit,
            VpnUser.is_blocked,
        )
        .filter_by(reseller_id=r.id, is_active=True)
    )
    if requested_user_ids:
        user_rows_query = user_rows_query.filter(VpnUser.id.in_(list(requested_user_ids)))

    user_rows = user_rows_query.all()

    if not user_rows:
        payload = {'ok': True, 'online': {}, 'errors': [], 'trimmed_sessions': []}
        if not enforce_auto and can_use_endpoint_cache:
            cache_set(cache_key, 10, payload)
        return jsonify(payload)

    # Filter to only show this reseller's users
    limit_map = {
        (username or '').strip().upper(): max(1, int(connection_limit or 1))
        for _user_id, username, connection_limit, _is_blocked in user_rows
    }

    snapshot = None
    if not prefer_fresh_snapshot:
        snapshot = get_cached_online_snapshot(int(r.server_id))
    if snapshot is not None:
        normalized_online = dict(snapshot.get('online_map') or {})
        normalized_devices = dict(snapshot.get('device_map') or {})
        normalized_connected_seconds = dict(snapshot.get('connected_seconds_map') or {})
    else:
        svc = SSHService(r.server)
        ok, online_map, device_map, connected_seconds_map, err = svc.get_online_user_snapshot()
        if not ok:
            return jsonify({'ok': False, 'msg': err, 'online': {}})

        normalized_online = {k.strip().upper(): v for k, v in online_map.items()}
        normalized_devices = (
            {k.strip().upper(): v for k, v in (device_map or {}).items()}
            if device_map is not None
            else {}
        )
        normalized_connected_seconds = {
            k.strip().upper(): v for k, v in (connected_seconds_map or {}).items()
        }
        cache_online_snapshot(
            int(r.server_id),
            normalized_online,
            device_map=normalized_devices,
            connected_seconds_map=normalized_connected_seconds,
        )

    trimmed_sessions: list[str] = []
    block_errors: list[str] = []

    if enforce_auto:
        svc = SSHService(r.server)
        trimmed_sessions, enforce_errors = auto_block_users_exceeding_limit(
            user_rows,
            normalized_online,
            svc,
            device_online_map=normalized_devices,
        )
        if enforce_errors:
            block_errors.extend(enforce_errors)
        if trimmed_sessions:
            ok_refresh, refreshed_online_map, refreshed_device_map, refreshed_connected_seconds_map, refresh_err = svc.get_online_user_snapshot()
            if ok_refresh:
                normalized_online = {k.strip().upper(): v for k, v in (refreshed_online_map or {}).items()}
            else:
                block_errors.append(f'No se pudo refrescar sesiones tras control automatico: {refresh_err}')

            if ok_refresh:
                normalized_devices = {
                    k.strip().upper(): v for k, v in (refreshed_device_map or {}).items()
                }
                normalized_connected_seconds = {
                    k.strip().upper(): v for k, v in (refreshed_connected_seconds_map or {}).items()
                }

            cache_online_snapshot(
                int(r.server_id),
                normalized_online,
                device_map=normalized_devices,
                connected_seconds_map=normalized_connected_seconds,
            )

    filtered: dict[str, dict[str, int]] = {}
    for username, limit in limit_map.items():
        devices_count = max(0, int(normalized_devices.get(username, 0) or 0))
        sessions_count = max(0, int(normalized_online.get(username, 0) or 0))
        observed_count = calculate_observed_connection_count(
            sessions_count,
            devices_count,
            has_device_metric=True,
        )
        if observed_count <= 0:
            continue
        filtered[username] = {
            'sessions': observed_count,
            'limit': limit,
            'connected_seconds': max(0, int(normalized_connected_seconds.get(username, 0) or 0)),
        }
    payload = {
        'ok': True,
        'online': filtered,
        'errors': block_errors,
        'trimmed_sessions': trimmed_sessions,
    }
    if not enforce_auto and can_use_endpoint_cache:
        cache_set(cache_key, 10, payload)
    return jsonify(payload)
