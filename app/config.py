import os
from datetime import timedelta
from cryptography.fernet import Fernet

class Config:
    BASE_DIR = os.path.dirname(os.path.dirname(__file__))
    
    # 基本配置
    SQLALCHEMY_DATABASE_URI = 'sqlite:///documents.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.urandom(24)
    
    # 會話配置
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    
    # 文件上傳配置
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'upload')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    
    # 加密配置
    ENCRYPTION_KEY_FILE = os.path.join(BASE_DIR, 'instance', 'encryption.key')
    _FERNET_INSTANCE = None
     
    
    @classmethod
    def get_encryption_key(cls):
        """獲取或創建加密密鑰"""
        if not os.path.exists(os.path.dirname(cls.ENCRYPTION_KEY_FILE)):
            os.makedirs(os.path.dirname(cls.ENCRYPTION_KEY_FILE))
            
        if os.path.exists(cls.ENCRYPTION_KEY_FILE):
            with open(cls.ENCRYPTION_KEY_FILE, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(cls.ENCRYPTION_KEY_FILE, 'wb') as f:
                f.write(key)
            return key
    
    @classmethod
    def get_fernet(cls):
        """獲取 Fernet 實例"""
        if cls._FERNET_INSTANCE is None:
            key = cls.get_encryption_key()
            cls._FERNET_INSTANCE = Fernet(key)
        return cls._FERNET_INSTANCE

    # 為了向後兼容，保留這些屬性
    @property
    def ENCRYPTION_KEY(self):
        return self.get_encryption_key()
    
    @property
    def FERNET(self):
        return self.get_fernet()
    
    # 配置郵件服務
