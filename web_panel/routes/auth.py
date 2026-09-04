from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from models import Admin, Reseller
from app import limiter

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        if isinstance(current_user, Admin):
            return redirect(url_for('admin.dashboard'))
        return redirect(url_for('reseller.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = Admin.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('admin.dashboard'))

        reseller = Reseller.query.filter_by(username=username).first()
        if reseller and reseller.check_password(password):
            if not reseller.is_active:
                flash('Tu cuenta está desactivada. Contacta al administrador.', 'danger')
                return render_template('login.html')
            login_user(reseller)
            return redirect(url_for('reseller.dashboard'))

        flash('Usuario o contraseña incorrectos.', 'danger')

    return render_template('login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))
