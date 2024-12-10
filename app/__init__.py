from flask import Flask, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
import os
from datetime import timedelta
from cryptography.fernet import Fernet 
from flask_mail import Mail

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
login_manager.login_view = 'main.login'
login_manager.login_message = '请先登录!'

# 加密管理器
class EncryptionManager:
    _instance = None
    _fernet = None
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    def __init__(self):
        self.key_file = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'instance',
            'encryption.key'
        )
    
    def get_encryption_key(self):
        if not os.path.exists(os.path.dirname(self.key_file)):
            os.makedirs(os.path.dirname(self.key_file))
            
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
            return key
    
    def get_fernet(self):
        if self._fernet is None:
            key = self.get_encryption_key()
            self._fernet = Fernet(key)
        return self._fernet
mail = Mail()
def create_app():
    app = Flask(__name__)
    
    # 基本配置
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://document_manage_database_user:1MbFj2uKLI0LZN7Afzp2LDpXtpAMhFyR@dpg-ct7jp8g8fa8c73bs6lj0-a.oregon-postgres.render.com/document_manage_database'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.urandom(24)
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
    app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'upload')
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
   
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # 例如使用 Gmail
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = 'huple30614@gmail.com'
    app.config['MAIL_PASSWORD'] = 'yxpsshyhxohyhczb'
    app.config['MAIL_DEFAULT_SENDER'] = 'huple30614@gmail.com'

    mail.init_app(app)

    # 初始化加密管理器並存儲在配置中
    encryption_manager = EncryptionManager.get_instance()
    app.config['ENCRYPTION_MANAGER'] = encryption_manager

    # 初始化擴展
    db.init_app(app)
    migrate.init_app(app, db)

    # 註冊藍圖
    from .routes import main
    app.register_blueprint(main)

    # 註冊命令
    from .cli import init_admin, delete_admin_command
    app.cli.add_command(init_admin)
    app.cli.add_command(delete_admin_command)

    @app.after_request
    def add_header(response):
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        if response.mimetype == 'application/pdf':
            response.headers['Content-Type'] = 'application/pdf'
        return response
    
    # 創建必要的目錄
    with app.app_context():
        for folder in [
            app.config['UPLOAD_FOLDER'],
            os.path.join(app.config['UPLOAD_FOLDER'], 'documents'),
            os.path.join(app.config['UPLOAD_FOLDER'], 'attachments')
        ]:
            if not os.path.exists(folder):
                os.makedirs(folder)

    return app