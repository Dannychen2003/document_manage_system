import os

# 獲取專案根目錄
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
instance_dir = os.path.join(BASE_DIR, 'instance')
key_file = os.path.join(instance_dir, 'encryption.key')

print("目錄結構檢查:")
print(f"instance 目錄: {instance_dir}")
print("包含的文件:")
for item in os.listdir(instance_dir):
    item_path = os.path.join(instance_dir, item)
    if os.path.isdir(item_path):
        print(f"  目錄: {item}")
    else:
        print(f"  文件: {item}")

if os.path.exists(key_file):
    print(f"\n找到加密密鑰文件: {key_file}")
    response = input("是否要刪除加密密鑰文件？(y/n): ")
    if response.lower() == 'y':
        os.remove(key_file)
        print("加密密鑰文件已刪除")
else:
    print("\n未找到加密密鑰文件")