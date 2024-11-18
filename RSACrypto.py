from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

from Crypto.Hash import MD5


class RSACrypto:
    """Класс для работы с RSA: шифрование, расшифрование, подпись и проверка подписей."""

    @staticmethod
    def generate_keys(key_size=2048) -> dict:
        """Генерация пары RSA ключей."""
        key = RSA.generate(key_size)
        public_key = key.publickey().export_key()
        private_key = key.export_key()
        return {"public_key": public_key, "private_key": private_key}

    @staticmethod
    def encrypt(data: str, public_key: bytes) -> str:
        """Шифрование данных."""
        key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(key)
        encrypted = cipher.encrypt(data.encode())
        return encrypted.hex()

    @staticmethod
    def decrypt(encrypted_data: str, private_key: bytes) -> str:
        """Расшифрование данных."""
        key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(key)
        decrypted = cipher.decrypt(bytes.fromhex(encrypted_data))
        return decrypted.decode()

    @staticmethod
    def sign(data: str, private_key: bytes) -> str:
        """Создание цифровой подписи для данных."""
        key = RSA.import_key(private_key)
        hasher = MD5.new(data.encode())
        signature = pkcs1_15.new(key).sign(hasher)
        return signature.hex()

    @staticmethod
    def verify(data: str, signature: str, public_key: bytes) -> bool:
        """Проверка цифровой подписи."""
        key = RSA.import_key(public_key)
        hasher = MD5.new(data.encode())
        try:
            pkcs1_15.new(key).verify(hasher, bytes.fromhex(signature))
            return True
        except (ValueError, TypeError):
            return False

if __name__ == "__main__":
    # Тестовые данные
    test_data = "Пример123!@#Test"
    keys = RSACrypto.generate_keys()

    # Шифрование и расшифровка
    encrypted = RSACrypto.encrypt(test_data, keys["public_key"])
    print("Encrypted:", encrypted)
    decrypted = RSACrypto.decrypt(encrypted, keys["private_key"])
    print("Decrypted:", decrypted)  # Ожидается: Пример123!@#Test

    # Подпись и проверка подписи
    signature = RSACrypto.sign(test_data, keys["private_key"])
    print("Signature:", signature)
    is_valid = RSACrypto.verify(test_data, signature, keys["public_key"])
    print("Signature valid:", is_valid)  # Ожидается: True

    # Проверка некорректной подписи
    is_valid_fake = RSACrypto.verify("Неверные данные", signature, keys["public_key"])
    print("Signature valid with wrong data:", is_valid_fake)  # Ожидается: False
