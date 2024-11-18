from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import MD5
from Crypto.Random import get_random_bytes


class DigitalSignature:
    @staticmethod
    def generate_keys():
        """Генерация пары ключей (для шифрования и подписания)"""
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key

    @staticmethod
    def encrypt_des_key(des_key, public_key):
        """Шифрование DES-ключа с использованием публичного ключа RSA"""
        rsa_key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        encrypted_des_key = cipher.encrypt(des_key)
        return encrypted_des_key

    @staticmethod
    def decrypt_des_key(encrypted_des_key, private_key):
        """Расшифровка DES-ключа с использованием приватного ключа RSA"""
        rsa_key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        des_key = cipher.decrypt(encrypted_des_key)
        return des_key

    @staticmethod
    def sign_data(message, des_key, private_key):
        """Создание подписи для хэша сообщения и DES-ключа"""
        h = MD5.new(message.encode() + des_key)
        rsa_key = RSA.import_key(private_key)
        signer = pkcs1_15.new(rsa_key)
        signature = signer.sign(h)
        return signature

    @staticmethod
    def verify_signature(message, des_key, signature, public_key):
        """Проверка подписи с использованием публичного ключа"""
        h = MD5.new(message.encode() + des_key)
        rsa_key = RSA.import_key(public_key)
        verifier = pkcs1_15.new(rsa_key)
        try:
            verifier.verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False
