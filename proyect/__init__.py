#Archivo de configuración que tiene la función de crear nuestra aplicación, iniciar la base de datos y registrará nuestros modelos
#Importamos el módulo os
import os
# IMPORTACIÓN AÑADIDA: Módulo para el manejo de logs
import logging
from logging.handlers import RotatingFileHandler
#Importamos la clase Flask del módulo flask
from flask import Flask
#Importamos la clase Security y SQLAlchemyUserDatastore de flask-security
from flask_security import Security, SQLAlchemyUserDatastore
#Importamos la función generate_password_hash de werkzeug.security
from werkzeug.security import generate_password_hash
#Importamos la clase SQLAlchemy del módulo flask_sqlalchemy
from flask_sqlalchemy import SQLAlchemy
 
#Creamos una instancia de SQLAlchemy
db = SQLAlchemy()
#Creamos el objeto SQLAlchemyUserDatastore con base a los modelos User y Role.
from .models import User, Role
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
 
#Método de inicio de la aplicación
def create_app():
    #Creamos una instancia de Flask
    app = Flask(__name__)
   
    # CONFIGURACIÓN DE LOGS AÑADIDA
    # Creamos un manejador que guarda el log en un archivo 'app_events.log'
    # maxBytes=1024*1024 (1MB) y mantiene hasta 10 archivos de respaldo
    file_handler = RotatingFileHandler('activity.log', maxBytes=1024*1024, backupCount=10)
    # Definimos el formato: Fecha y Hora - Nivel de importancia - Mensaje
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s ' #[en %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)

    # REGISTRO DE EVENTO: Inicio de la aplicación
    app.logger.info('=' * 60)
    app.logger.info('INICIO DE APLICACIÓN: Sistema de Autenticación iniciado.')
    app.logger.info('=' * 60)

    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    #Generamos la clave aleatoria de sesión Flask para crear una cookie con la inf. de la sesión
    app.config['SECRET_KEY'] = os.urandom(24)
    #Definimos la ruta a la BD: mysql://user:password@localhost/bd'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root@127.0.0.1/flasksecurity'
    # We're using PBKDF2 with salt.
    app.config['SECURITY_PASSWORD_HASH'] = 'pbkdf2_sha512'
    app.config['SECURITY_PASSWORD_SALT'] = 'thisissecretsalt'
 
    #Conectando los modelos a fask-security usando SQLAlchemyUserDatastore
    security = Security(app, user_datastore)
 
    #Inicializamos y creamos la BD
    db.init_app(app)
   
    #@app.before_first_request
    with app.app_context():
        # your code here to do things before first request
        @app.before_request
        def create_all():
            # The following line will remove this handler, making it only run on the first request
            app.before_request_funcs[None].remove(create_all)
            # Create any database tables that don't exist yet.
            db.create_all()
 
            # Create the Roles "admin" and "end-user" -- unless they already exist
            user_datastore.find_or_create_role(name='admin', description='Administrator')
            user_datastore.find_or_create_role(name='end-user', description='End user')
 
            # Create two Users for testing purposes -- unless they already exists.
            # In each case, use Flask-Security utility function to encrypt the password.
            #encrypted_password = utils.encrypt_password('password')
            encrypted_password = generate_password_hash('password', method='pbkdf2:sha256')
 
            if not user_datastore.find_user(email='juan@example.com'):
                user_datastore.create_user(name='Juan', email='juan@example.com', password=encrypted_password)
            if not user_datastore.find_user(email='admin@example.com'):
                user_datastore.create_user(name='Ismael', email='admin@example.com', password=encrypted_password)
 
            # Commit any database changes; the User and Roles must exist before we can add a Role to the User
            db.session.commit()
 
            # Give one User has the "end-user" role, while the other has the "admin" role. (This will have no effect if the
            # Users already have these Roles.) Again, commit any database changes.
            user_datastore.add_role_to_user(user_datastore.find_user(email='juan@example.com'), 'end-user')
            user_datastore.add_role_to_user(user_datastore.find_user(email='admin@example.com'), 'admin')
            db.session.commit()
 
    #Registramos el blueprint para las rutas auth de la aplicación
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)
 
    #Registramos el blueprint para las partes no auth de la aplicación
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    # MANEJADORES DE ERROR: Registrar errores 404 y 500 en el log
    @app.errorhandler(404)
    def not_found_error(error):
        from flask import request
        app.logger.warning(
            f'ERROR 404 - Página no encontrada: {request.url} '
            f'desde IP: {request.remote_addr}'
        )
        return 'Página no encontrada', 404

    @app.errorhandler(500)
    def internal_error(error):
        from flask import request
        db.session.rollback()
        app.logger.error(
            f'ERROR 500 - Error interno del servidor en: {request.url} '
            f'desde IP: {request.remote_addr} | Detalle: {error}'
        )
        return 'Error interno del servidor', 500

    return app