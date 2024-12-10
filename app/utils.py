import hashlib
import rsa
from cryptography.fernet import Fernet
import base64
import os
from flask import current_app
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import serialization

def generate_aes_key():
    """生成 AES 密鑰"""
    return os.urandom(32)

def encrypt_with_aes(content: bytes, aes_key: bytes) -> str:
    """使用 AES 密鑰加密內容，返回 Base64 編碼的字符串"""
    iv = os.urandom(16)  # 初始化向量
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    # 添加 PKCS7 padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(content) + padder.finalize()
    
    # 加密
    encrypted_content = encryptor.update(padded_data) + encryptor.finalize()
    
    # 組合 IV 和加密內容，並進行 Base64 編碼
    return base64.b64encode(iv + encrypted_content).decode('utf-8')


def decrypt_with_aes(encrypted_content: str, aes_key: bytes) -> bytes:
    """使用 AES 密鑰解密內容，返回原始的二進位數據"""
    # 解碼 Base64
    encrypted_data = base64.b64decode(encrypted_content.encode('utf-8'))
    
    # 分離 IV 和加密內容
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    
    # 解密
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # 移除 padding
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    return data


def encrypt_aes_key(aes_key: bytes, public_key_pem: str) -> str:
    """使用接收者的公鑰加密 AES 密鑰，返回 Base64 編碼的字符串"""
    public_key_obj = serialization.load_pem_public_key(public_key_pem.encode())
    encrypted_key = public_key_obj.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_key).decode('utf-8')



def decrypt_aes_key(encrypted_key: str, private_key_pem: str) -> bytes:
    """使用私鑰解密 AES 密鑰，返回原始的 AES 密鑰"""
    private_key_obj = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None
    )
    encrypted_key_bytes = base64.b64decode(encrypted_key.encode())
    decrypted_key = private_key_obj.decrypt(
        encrypted_key_bytes,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key

def get_fernet():
    """獲取 Fernet 實例"""
    try:
        encryption_manager = current_app.config['ENCRYPTION_MANAGER']
        return encryption_manager.get_fernet()
    except Exception as e:
        print(f"獲取 Fernet 實例時出錯: {str(e)}")
        # 如果沒有加密管理器，創建一個新的
        from cryptography.fernet import Fernet
        import os

        # 確保 instance 目錄存在
        instance_dir = os.path.join(current_app.root_path, '..', 'instance')
        os.makedirs(instance_dir, exist_ok=True)

        # 密鑰文件路徑
        key_file = os.path.join(instance_dir, 'encryption.key')

        # 如果密鑰文件不存在，創建新密鑰
        if not os.path.exists(key_file):
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
        else:
            # 讀取現有密鑰
            with open(key_file, 'rb') as f:
                key = f.read()

        return Fernet(key)

def create_digital_signature_combined(content: bytes, signature_message: str, private_key_pem: str, previous_signature: str = "") -> str:
    """
    創建數位簽章 - 包含前一次簽章數據
    """
    try:
        private_key = rsa.PrivateKey.load_pkcs1(private_key_pem.encode())
        # 組合內容、簽署訊息與前一次簽章
        combined_content = content + signature_message.encode() + previous_signature.encode()
        # 計算摘要
        combined_hash = hashlib.sha256(combined_content).hexdigest()
        # 創建簽章
        signature = rsa.sign(combined_hash.encode(), private_key, 'SHA-256')
        return base64.b64encode(signature).decode()
    except Exception as e:
        print(f"創建數位簽章（包含前一次簽章）時發生錯誤: {str(e)}")
        raise

def verify_signature_combined(content: bytes, signature: str, public_key_pem: str, signature_message: str, previous_signature: str = "") -> bool:
    """
    驗證數位簽章 - 包含前一次簽章數據
    """
    try:
        public_key = rsa.PublicKey.load_pkcs1(public_key_pem.encode())
        # 組合內容、簽署訊息與前一次簽章
        combined_content = content + signature_message.encode() + previous_signature.encode()
        # 計算摘要
        combined_hash = hashlib.sha256(combined_content).hexdigest()
        # 解碼簽章
        signature_bytes = base64.b64decode(signature)
        
        # 驗證簽章
        rsa.verify(combined_hash.encode(), signature_bytes, public_key)
        return True
    except rsa.VerificationError:
        return False
    except Exception as e:
        print(f"驗證簽章（包含前一次簽章）時發生錯誤: {str(e)}")
        return False
def decrypt_private_key(encrypted_private_key):
    """解密私鑰"""
    try:
        if not encrypted_private_key:
            raise ValueError("加密的私鑰為空")
        
        fernet = get_fernet()
        print(f"開始解密私鑰...")
        
        if isinstance(encrypted_private_key, str):
            encrypted_private_key = encrypted_private_key.encode()
        
        decrypted_data = fernet.decrypt(encrypted_private_key)
        decrypted_str = decrypted_data.decode()
        
        print("私鑰解密成功")
        return decrypted_str
        
    except Exception as e:
        print(f"解密錯誤: {type(e).__name__} - {str(e)}")
        raise ValueError("私鑰解密失敗") from e


def generate_keys():
    """生成 RSA 密鑰對並返回 PEM 格式的私鑰和公鑰"""
    (public_key, private_key) = rsa.newkeys(2048)
    private_pem = private_key.save_pkcs1().decode()
    public_pem = public_key.save_pkcs1().decode()
    return private_pem, public_pem

def encrypt_private_key(private_key):
    """加密私鑰"""
    try:
        if not private_key:
            raise ValueError("私鑰為空")
        
        fernet = get_fernet()
        print(f"開始加密私鑰...")
        
        if isinstance(private_key, str):
            private_key = private_key.encode()
        
        encrypted_data = fernet.encrypt(private_key)
        print("私鑰加密成功")
        return encrypted_data.decode()
        
    except Exception as e:
        print(f"加密錯誤: {type(e).__name__} - {str(e)}")
        raise ValueError("私鑰加密失敗") from e
def test_encryption():
    """測試加密/解密功能"""
    try:
        test_data = "test_string"
        encrypted = encrypt_private_key(test_data)
        decrypted = decrypt_private_key(encrypted)
        assert test_data == decrypted
        print("加密/解密測試成功")
        return True
    except Exception as e:
        print(f"加密/解密測試失敗: {str(e)}")
        return False