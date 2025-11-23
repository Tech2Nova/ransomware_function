# symmetric.py (完整修复版)

import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

class AESCipher(object):
    def __init__(self, key):
        self.bs = 32
        if isinstance(key, str):
            key = key.encode('utf-8')
        self.key = hashlib.sha256(key).digest()

    def encrypt(self, raw):
        if isinstance(raw, str):
            raw = raw.encode('utf-8')
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc, decryption_key=None):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        if(decryption_key):
            if isinstance(decryption_key, str):
                decryption_key = decryption_key.encode('utf-8')
            self.key = hashlib.sha256(decryption_key).digest()
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:]))

    def _pad(self, s):
        # 填充为 bytes
        pad_len = self.bs - len(s) % self.bs
        return s + bytes([pad_len]) * pad_len

    @staticmethod
    def _unpad(s):
        return s[:-s[-1]]

if __name__ == "__main__":
    import generate_keys
    key = generate_keys.generate_key(256, True)
    cipher_obj = AESCipher(key)
    print("chave: {}".format(key))
    enc = cipher_obj.encrypt(b"TESTE CRYPTO")  # 使用 bytes
    print(enc)
    back = cipher_obj.decrypt(enc, key)
    print(back)