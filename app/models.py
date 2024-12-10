from datetime import datetime
from app import db
from hashlib import sha256
import secrets

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    account = db.Column(db.String(80), unique=True, nullable=False)  # 新增帳號欄位
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)  # 新增郵箱欄位
    department = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(20))
    extension = db.Column(db.String(10))
    is_admin = db.Column(db.Boolean, default=False)  # 新增管理員標記
    force_password_change = db.Column(db.Boolean, default=True)  # 新增強制修改密碼標記
    reset_token = db.Column(db.String(100))  # 新增重置令牌
    public_key = db.Column(db.Text)  # 新增公鑰
    private_key_encrypted = db.Column(db.Text)  # 修改為加密的私鑰
    created_at = db.Column(db.DateTime, default=datetime.now)
    salt = db.Column(db.String(32), nullable=False)  # 新增鹽值欄位
    is_general_recipient = db.Column(db.Boolean, default=False)  # 新增總收文人員標記

    def set_password(self, password):
        # 生成隨機鹽值
        self.salt = secrets.token_hex(16)
        # 組合密碼和鹽值後進行 SHA-256 加密
        password_hash = sha256((password + self.salt).encode()).hexdigest()
        self.password = password_hash

    def check_password(self, password):
        # 使用相同的鹽值驗證密碼
        password_hash = sha256((password + self.salt).encode()).hexdigest()
        return self.password == password_hash

    def set_encrypted_private_key(self, private_key_plain, encrypt_func):
        # 使用傳入的加密函數加密私鑰
        self.private_key_encrypted = encrypt_func(private_key_plain)

    def get_decrypted_private_key(self, decrypt_func):
        # 使用傳入的解密函數解密私鑰
        return decrypt_func(self.private_key_encrypted)
class Document(db.Model):
    __tablename__ = 'documents'
    
    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.String(20), unique=True)  # 公文編號
    type = db.Column(db.String(50))  # 公文類型
    subject = db.Column(db.String(200))  # 主旨
    description = db.Column(db.Text)  # 內容描述
    deadline = db.Column(db.DateTime)  # 期限
    status = db.Column(db.String(20))  # 公文狀態
    urgency = db.Column(db.String(20))  # 緊急程度
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # 建立者
    file_path = db.Column(db.String(255))  # 主文件路徑
    current_handler_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # 當前處理人
    current_order = db.Column(db.Integer, default=1)  # 當前處理順序
    created_at = db.Column(db.DateTime, default=datetime.now) 
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    classification= db.Column(db.String(50))  # 密等
    initial_signature = db.Column(db.Text)    # 初始簽章
    initial_signature_message = db.Column(db.String(500), nullable=True)  # 新增此字段
    encrypted_content = db.Column(db.Text)  # 加密後的內容
    encrypted_aes_key = db.Column(db.Text)  # 加密後的 AES 密鑰
    current_encryption_user_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # 當前加密用戶
    archive_reason = db.Column(db.String(500), nullable=True)  # 新增銷號理由欄位
    reassign_reason = db.Column(db.String(500))  # 新增改分原因欄位
    
    # 關聯
    creator = db.relationship('User', foreign_keys=[creator_id], backref='created_documents')
    current_handler = db.relationship('User', foreign_keys=[current_handler_id], backref='pending_documents')
    forwards = db.relationship('Forward', backref='document', lazy='dynamic')

class Attachment(db.Model):
    __tablename__ = 'attachments'
    
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)  # 文件名
    file_path = db.Column(db.String(255), nullable=False)  # 存儲路徑
    file_size = db.Column(db.Integer)  # 文件大小
    file_type = db.Column(db.String(50))  # 文件類型
    description = db.Column(db.Text)  # 附件描述
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    document = db.relationship('Document', backref=db.backref('attachments_list', lazy=True))

class Forward(db.Model):
    __tablename__ = 'forwards'
    
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    order = db.Column(db.Integer, nullable=False)  # 處理順序
    is_approver = db.Column(db.Boolean, default=False)  # 是否為決行者
    status = db.Column(db.String(20), default='待簽核')  # 狀態：待簽核、已簽核、退件
    signature_date = db.Column(db.DateTime)  # 簽核時間
    created_at = db.Column(db.DateTime, default=datetime.now)
    signature = db.Column(db.Text)           # 數位簽章
    signature_message = db.Column(db.Text)    # 簽章附加訊息
    
    # 關聯
    user = db.relationship('User', backref='forwards')