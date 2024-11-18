# File: RSACrypto.py
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes


class RSACrypto:
    """Класс для работы с шифрованием и расшифрованием RSA."""

    @staticmethod
    def generate_keys(key_size=2048) -> dict:  # Увеличили размер ключа до 2048
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

# Тестирование
if __name__ == "__main__":
    test_data = "Пример123!@#Test"
    keys = RSACrypto.generate_keys()
    encrypted = RSACrypto.encrypt(test_data, keys["public_key"])
    print("Encrypted:", encrypted)
    decrypted = RSACrypto.decrypt(encrypted, keys["private_key"])
    print("Decrypted:", decrypted)  # Ожидаемый вывод: исходная строка `test_data`
