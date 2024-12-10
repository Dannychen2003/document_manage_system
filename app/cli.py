import click
from flask.cli import with_appcontext
from flask import current_app
from app import db
from app.models import User, Forward
from app.utils import generate_keys, encrypt_private_key

@click.command('delete-admin')
@with_appcontext
def delete_admin_command():
    try:
        # 查找管理員帳號
        admin = User.query.filter_by(account='admin').first()
        
        if admin:
            # 先刪除所有關聯的 forwards 記錄
            Forward.query.filter_by(user_id=admin.id).delete()
            
            # 最後刪除管理員帳號
            db.session.delete(admin)
            db.session.commit()
            click.echo('管理員帳號及相關數據已成功刪除')
        else:
            click.echo('未找到管理員帳號')
            
    except Exception as e:
        db.session.rollback()
        click.echo(f'刪除管理員帳號時發生錯誤: {str(e)}')

@click.command('init-admin')
@with_appcontext
def init_admin():
    """初始化系統管理員帳號"""
    try:
        # 檢查是否已存在管理員
        admin = User.query.filter_by(account='admin').first()
        if admin:
            click.echo('管理員帳號已存在')
            return

        # 生成密鑰對
        private_key_pem, public_key_pem = generate_keys()
        
        # 使用應用配置中的加密密鑰進行加密
        try:
            encrypted_private_key = encrypt_private_key(private_key_pem)
            print("私鑰加密成功")
        except Exception as e:
            click.echo(f'私鑰加密失敗: {str(e)}')
            return

        # 創建新管理員
        admin = User(
            username='System Admin',
            account='admin',
            email='admin@example.com',
            department='IT',
            public_key=public_key_pem,
            private_key_encrypted=encrypted_private_key,
            is_admin=True,
            force_password_change=True
        )
        admin.set_password('123456')
        
        db.session.add(admin)
        db.session.commit()
        
        click.echo('管理員帳號創建成功！')
        click.echo('請使用以下信息登入：')
        click.echo('帳號: admin')
        click.echo('密碼: 123456')
        click.echo('首次登入後請立即修改密碼！')
        
    except Exception as e:
        db.session.rollback()