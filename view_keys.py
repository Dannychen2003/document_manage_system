from app import create_app, db
from sqlalchemy import text
import os

app = create_app()

def view_user_keys(user_id=None):
    with app.app_context():
        connection = db.session.connection()
        try:
            # 基本查詢，選擇現有的欄位
            query = """
                SELECT u.id, u.username, u.department, u.public_key, u.private_key_encrypted 
                FROM users u 
            """
            params = {}
            
            # 如果指定了用戶ID，添加WHERE條件
            if user_id:
                query += " WHERE u.id = :user_id"
                params["user_id"] = user_id
            
            query += " ORDER BY u.id"
            
            users = connection.execute(text(query), params).fetchall()
            
            if not users:
                print("找不到用戶" if user_id else "沒有用戶記錄")
                return
            
            for user in users:
                print("\n" + "="*50)
                print(f"用戶ID: {user.id}")
                print(f"用戶名: {user.username}")
                print(f"部門: {user.department}")
                print("-"*50)
                
                # 顯示公鑰
                if user.public_key:
                    print("\n公鑰:")
                    print(user.public_key)
                else:
                    print("\n未設置公鑰")
                
                # 顯示私鑰（加密後）
                if user.private_key_encrypted:
                    print("\n加密後的私鑰:")
                    print(user.private_key_encrypted)
                else:
                    print("\n未設置私鑰")
                
                # 選項：保存密鑰到文件
                save = input("\n是否要將密鑰保存到文件？(y/n): ")
                if save.lower() == 'y':
                    # 創建用戶目錄
                    dir_name = f"user_{user.id}_keys"
                    os.makedirs(dir_name, exist_ok=True)
                    
                    # 保存公鑰
                    if user.public_key:
                        with open(f"{dir_name}/public_key.pem", "w") as f:
                            f.write(user.public_key)
                    
                    # 保存加密後的私鑰
                    if user.private_key_encrypted:
                        with open(f"{dir_name}/private_key_encrypted.pem", "w") as f:
                            f.write(user.private_key_encrypted)
                    
                    print(f"密鑰已保存到 {dir_name} 目錄")

        except Exception as e:
            print(f"查詢失敗：{str(e)}")

def list_users():
    with app.app_context():
        connection = db.session.connection()
        try:
            users = connection.execute(
                text("SELECT id, username, department FROM users ORDER BY id")
            ).fetchall()
            print("\n當前用戶列表：")
            print("ID\t用戶名\t\t部門")
            print("-" * 40)
            for user in users:
                print(f"{user.id}\t{user.username}\t\t{user.department}")
        except Exception as e:
            print(f"列出用戶失敗：{str(e)}")

# 主選單
while True:
    print("\n密鑰管理系統")
    print("1. 列出所有用戶")
    print("2. 查看特定用戶的密鑰")
    print("3. 查看所有用戶的密鑰")
    print("4. 退出")
    
    choice = input("請選擇操作 (1-4): ")
    
    if choice == "1":
        list_users()
    elif choice == "2":
        list_users()
        user_id = input("\n請輸入要查看的用戶ID: ")
        try:
            user_id = int(user_id)
            view_user_keys(user_id)
        except ValueError:
            print("無效的用戶ID")
    elif choice == "3":
        confirm = input("確定要查看所有用戶的密鑰嗎？(y/n): ")
        if confirm.lower() == 'y':
            view_user_keys()
        else:
            print("取消操作")
    elif choice == "4":
        print("退出程序")
        break
    else:
        print("無效的選擇，請重試")