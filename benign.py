# 文件名: benign.py
import os
import shutil
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

# ==================== 配置区 ====================
TARGET_DIR = Path("/root/")          # 要加密的目录
BACKUP_DIR = TARGET_DIR / ".encrypt_backup"  # 备份目录（隐藏）
KEY_FILE   = Path("/root/.file_encrypt_key.bin")  # 密钥保存位置（非常重要！）

# 如果你想每次都生成新密钥（加密后旧文件将永远无法解密！），改为 True
GENERATE_NEW_KEY_EACH_TIME = False
# ================================================

def generate_key():
    """生成 256 位 AES 密钥"""
    return AESGCM.generate_key(bit_length=256)

def save_key(key: bytes, key_path: Path):
    key_path.parent.mkdir(parents=True, exist_ok=True)
    # 用 600 权限保存密钥，只有 root 可读写
    key_path.write_bytes(key)
    key_path.chmod(0o600)

def load_key(key_path: Path) -> bytes:
    if not key_path.exists():
        print("未找到密钥文件，生成新密钥…")
        key = generate_key()
        save_key(key, key_path)
        return key
    return key_path.read_bytes()

def encrypt_file(file_path: Path, key: bytes, backup_dir: Path):
    # 1. 备份原文件
    rel_path = file_path.relative_to(TARGET_DIR)
    backup_path = backup_dir / rel_path
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(file_path, backup_path)
    
    # 2. 读取原文件内容
    data = file_path.read_bytes()
    
    # 3. 生成随机 nonce（12字节最优）
    nonce = secrets.token_bytes(12)
    
    # 4. 加密
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)  # None = 无附加认证数据
    
    # 5. 写入加密文件：nonce（12） + ciphertext
    file_path.write_bytes(nonce + ciphertext)
    

def main():
    print("=== AES-256-GCM 文件批量加密工具 ===\n")
    
    if not TARGET_DIR.exists():
        print(f"错误：目录 {TARGET_DIR} 不存在！")
        return
    
    # 加载或生成主密钥
    if GENERATE_NEW_KEY_EACH_TIME or not KEY_FILE.exists():
        key = generate_key()
        save_key(key, KEY_FILE)
    else:
        key = load_key(KEY_FILE)
    
    # 创建备份目录
    BACKUP_DIR.mkdir(exist_ok=True)
    print(f"原文件将备份到：{BACKUP_DIR}\n")
    
    # 开始遍历加密
    file_count = 0
    for file_path in TARGET_DIR.rglob("*"):
        if file_path.is_file():
            # 跳过我们自己创建的备份目录和密钥文件
            if BACKUP_DIR in file_path.parents or file_path == KEY_FILE:
                continue
                
            file_count += 1
            try:
                encrypt_file(file_path, key, BACKUP_DIR)
            except Exception as e:
                print(f"   加密失败：{e}")
    
    print(f"benign加密完成！共处理 {file_count} 个文件")


if __name__ == "__main__":
    # 必须用 root 运行
    if os.getuid() != 0:
        print("错误：必须使用 root 权限运行此脚本！")
        print("请执行：sudo python3 encrypt_root_test.py")
        exit(1)
    
    main()
