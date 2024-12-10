from app import create_app, db
from app.models import User

app = create_app()
with app.app_context():
    # 列出所有用戶
    def list_users():
        users = User.query.all()
        print("\n當前用戶列表：")
        print("ID\t用戶名\t\t部門")
        print("-" * 40)
        for user in users:
            print(f"{user.id}\t{user.username}\t\t{user.department}")

    # 刪除用戶
    def delete_user(user_id):
        user = User.query.get(user_id)
        if user:
            try:
                db.session.delete(user)
                db.session.commit()
                print(f"成功刪除用戶：{user.username}")
            except Exception as e:
                db.session.rollback()
                print(f"刪除失敗：{str(e)}")
        else:
            print(f"找不到ID為 {user_id} 的用戶")

    # 主選單
    while True:
        print("\n用戶管理系統")
        print("1. 列出所有用戶")
        print("2. 刪除用戶")
        print("3. 退出")
        
        choice = input("請選擇操作 (1-3): ")
        
        if choice == "1":
            list_users()
        elif choice == "2":
            list_users()
            user_id = input("\n請輸入要刪除的用戶ID: ")
            try:
                user_id = int(user_id)
                delete_user(user_id)
            except ValueError:
                print("無效的用戶ID")
        elif choice == "3":
            print("退出程序")
            break
        else:
            print("無效的選擇，請重試")