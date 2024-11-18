from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes


class DESCrypto:
    """Класс для работы с шифрованием и расшифрованием DES."""

    DES_KEY_SIZE = 8  # Размер ключа для DES

    @staticmethod
    def pad_data(data: bytes) -> bytes:
        """Дополнение данных до длины, кратной 8 байтам, по схеме PKCS7."""
        padding_length = DESCrypto.DES_KEY_SIZE - (len(data) % DESCrypto.DES_KEY_SIZE)
        return data + bytes([padding_length] * padding_length)

    @staticmethod
    def unpad_data(data: bytes) -> bytes:
        """Удаление дополнения из данных."""
        padding_length = data[-1]
        return data[:-padding_length]

    @staticmethod
    def generate_key() -> bytes:
        """Генерация случайного ключа DES."""
        return get_random_bytes(DESCrypto.DES_KEY_SIZE)

    @staticmethod
    def encrypt(data: str, key: bytes, iv: bytes) -> str:
        """Шифрование данных с использованием DES."""
        if len(key) != DESCrypto.DES_KEY_SIZE:
            raise ValueError("Ключ должен быть длиной 8 байт.")
        cipher = DES.new(key, DES.MODE_CBC, iv)
        padded_data = DESCrypto.pad_data(data.encode())
        encrypted_data = cipher.encrypt(padded_data)
        return encrypted_data.hex()

    @staticmethod
    def decrypt(encrypted_data: str, key: bytes, iv: bytes) -> str:
        """Расшифрование данных с использованием DES."""
        if len(key) != DESCrypto.DES_KEY_SIZE:
            raise ValueError("Ключ должен быть длиной 8 байт.")
        cipher = DES.new(key, DES.MODE_CBC, iv)
        decrypted_padded_data = cipher.decrypt(bytes.fromhex(encrypted_data))
        return DESCrypto.unpad_data(decrypted_padded_data).decode()


# Тестирование DESCrypto
if __name__ == "__main__":
    test_data = "Пример123!@#Test"
    key = DESCrypto.generate_key()
    iv = get_random_bytes(DESCrypto.DES_KEY_SIZE)
    print("Generated Key:", key.hex())
    print("Generated IV:", iv.hex())
    encrypted = DESCrypto.encrypt(test_data, key, iv)
    print("Encrypted Data:", encrypted)
    decrypted = DESCrypto.decrypt(encrypted, key, iv)
    print("Decrypted Data:", decrypted)  # Ожидаемый вывод: исходная строка `test_data`
