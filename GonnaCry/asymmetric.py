# asymmetric.py (完整修复版)

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

class Asymmetric:
    def __init__(self, bit_len=2048):
        self.bit_len = bit_len
        self.key = None
        self.private_key_PEM = None
        self.public_key_PEM = None

    def generate_keys(self):
        self.key = RSA.generate(self.bit_len)
        self.private_key_PEM = self.key.exportKey('PEM')
        self.public_key_PEM = self.key.publickey().exportKey('PEM')

    def encrypt(self, data):
        public_key = RSA.import_key(self.public_key_PEM)
        cipher = PKCS1_OAEP.new(public_key)
        return cipher.encrypt(data)

    def decrypt(self, encrypted_data):
        private_key = RSA.import_key(self.private_key_PEM)
        cipher = PKCS1_OAEP.new(private_key)
        return cipher.decrypt(encrypted_data)