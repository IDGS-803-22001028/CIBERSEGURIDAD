from flask import Flask, Blueprint, render_template, redirect, url_for, request, flash, current_app
from werkzeug.security import generate_password_hash, check_password_hash

from flask_security import login_required
from flask_security.utils import login_user, logout_user

from .models import User
from . import db, user_datastore

auth = Blueprint('auth', __name__, url_prefix='/security')

@auth.route('/login')
def login():
    return render_template('/security/login.html')

@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        current_app.logger.warning(
            f'FALLO DE LOGIN: Intento fallido para el correo: {email} '
            f'desde IP: {request.remote_addr}'
        )
        flash('el email y/o la contraseña son incorrectos.')
        return redirect(url_for('auth.login'))

    login_user(user, remember=remember)
    current_app.logger.info(
        f'LOGIN EXITOSO: Usuario {user.email} (ID: {user.id}) '
        f'inició sesión desde IP: {request.remote_addr}'
    )
    
    return redirect(url_for('main.profile'))

@auth.route('/register', methods=['GET'])
def register():
    return render_template('/security/register.html')

@auth.route('/register', methods=['POST'])
def register_post():
    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')

    user = User.query.filter_by(email=email).first()

    if user:
        current_app.logger.warning(
            f'REGISTRO FALLIDO: Intento de crear cuenta con correo ya existente: {email} '
            f'desde IP: {request.remote_addr}'
        )
        flash('Ese correo electrónico ya existe.')
        return redirect(url_for('auth.register'))

    user_datastore.create_user(
        name=name, 
        email=email, 
        password=generate_password_hash(password, method='pbkdf2:sha256')
    )
    db.session.commit()

    current_app.logger.info(
        f'NUEVO USUARIO: Nueva cuenta registrada: {email} '
        f'desde IP: {request.remote_addr}'
    )

    return redirect(url_for('auth.login'))

@auth.route('/logout')
@login_required
def logout():
    from flask_security import current_user
    email_log = current_user.email
    logout_user()
    current_app.logger.info(f'LOGOUT: Usuario {email_log} ha cerrado sesión.')
    
    return redirect(url_for('main.index'))