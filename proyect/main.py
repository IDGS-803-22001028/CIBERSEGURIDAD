from flask import Blueprint, current_app, render_template, request
from flask_security import login_required, current_user
from flask_security.decorators import roles_required

from . import db

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('security/index.html')

@main.route('/profile')
@login_required
def profile():
    current_app.logger.info(
        f'ACCESO A PERFIL: Usuario {current_user.email} (ID: {current_user.id}) '
        f'accedió a su perfil desde IP: {request.remote_addr}'
    )
    return render_template('security/profile.html', name=current_user.name, email=current_user.email)