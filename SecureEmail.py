from DESCrypto import DESCrypto
from DigitalSignature import DigitalSignature
from Crypto.Random import get_random_bytes


class SecureEmail:
    """Класс для обработки шифрования письма и добавления цифровой подписи."""

    @staticmethod
    def process_email(email_body: bytes, attachments: list, private_key_sign: bytes, public_key_encrypt: bytes):
        """
        Шифрует тело письма, вложения и подписывает письмо.

        :param email_body: тело письма в байтах
        :param attachments: список вложений в формате {'filename': str, 'content': bytes}
        :param private_key_sign: приватный ключ для подписи
        :param public_key_encrypt: публичный ключ для шифрования DES-ключа
        :return: зашифрованные данные в байтовом формате
        """
        des_key = DESCrypto.generate_key()  # Генерация DES-ключа
        iv = get_random_bytes(DESCrypto.DES_KEY_SIZE)  # Генерация IV

        # Шифрование текущего тела письма
        encrypted_content = DESCrypto.encrypt(email_body, des_key, iv)

        # Шифрование содержимого вложений
        encrypted_attachments = []
        for attachment in attachments:
            encrypted_attachments.append({
                "filename": attachment["filename"],
                "content": DESCrypto.encrypt(attachment["content"], des_key, iv)
            })

        # Шифрование DES-ключа с использованием публичного ключа
        encrypted_des_key = DigitalSignature.encrypt_des_key(des_key, public_key_encrypt)

        # Подписание данных (content + DES-ключ)
        signature = DigitalSignature.sign_data(encrypted_content, des_key, private_key_sign)

        # Возвращаем данные в байтовом представлении
        return iv, encrypted_des_key, signature, encrypted_content, encrypted_attachments

    @staticmethod
    def verify_email(iv: bytes, encrypted_des_key: bytes, signature: bytes, encrypted_content: bytes,
                     encrypted_attachments: list, private_key_encrypt: bytes, public_key_sign: bytes):
        """
        Проверяет подпись и расшифровывает письмо и вложения.

        :param iv: инициализационный вектор
        :param encrypted_des_key: зашифрованный DES-ключ
        :param signature: цифровая подпись
        :param encrypted_content: зашифрованное тело письма
        :param encrypted_attachments: зашифрованные вложения
        :param private_key_encrypt: приватный ключ для расшифровки DES-ключа
        :param public_key_sign: публичный ключ для проверки подписи
        :return: расшифрованные данные
        """
        # Расшифровка DES-ключа
        des_key = DigitalSignature.decrypt_des_key(encrypted_des_key, private_key_encrypt)

        # Проверка подписи
        is_valid = DigitalSignature.verify_signature(encrypted_content, des_key, signature, public_key_sign)
        if not is_valid:
            raise ValueError("Цифровая подпись недействительна.")

        # Расшифровка тела письма
        decrypted_content = DESCrypto.decrypt(encrypted_content, des_key, iv)

        # Расшифровка содержимого вложений
        decrypted_attachments = []
        for attachment in encrypted_attachments:
            decrypted_attachments.append({
                "filename": attachment["filename"],
                "content": DESCrypto.decrypt(attachment["content"], des_key, iv)
            })

        # Возвращаем расшифрованные данные
        return decrypted_content, decrypted_attachments


# Пример использования SecureEmail
if __name__ == "__main__":
    # Пример данных письма и вложений (в бинарном виде)
    email_body = "Тестовое письмо".encode("utf-8")
    attachments = [
        {"filename": "example_filename_1", "content": b"attachment_content_1"},
        {"filename": "example_filename_2", "content": b"attachment_content_2"},
    ]

    # Генерация пар ключей для подписи и шифрования
    private_key_sign, public_key_sign = DigitalSignature.generate_keys()
    private_key_encrypt, public_key_encrypt = DigitalSignature.generate_keys()

    # Обработка письма
    iv, encrypted_des_key, signature, encrypted_content, encrypted_attachments = SecureEmail.process_email(
        email_body, attachments, private_key_sign, public_key_encrypt)

    # Вывод зашифрованных данных в байтовом представлении
    print("Encrypted Email:")
    print(f"IV: {iv.hex()}")
    print(f"Encrypted DES Key: {encrypted_des_key.hex()}")
    print(f"Signature: {signature.hex()}")
    print(f"Encrypted Content: {encrypted_content.hex()}")
    for attachment in encrypted_attachments:
        print(f"Encrypted Attachment {attachment['filename']}: {attachment['content'].hex()}")

    # Проверка и расшифровка письма
    decrypted_content, decrypted_attachments = SecureEmail.verify_email(
        iv,
        encrypted_des_key,
        signature,
        encrypted_content,
        encrypted_attachments,
        private_key_encrypt,
        public_key_sign
    )

    # Вывод расшифрованных данных
    print("\nDecrypted Email:")
    print(f"Decrypted Content: {decrypted_content.decode()}")
    for attachment in decrypted_attachments:
        print(f"Decrypted Attachment {attachment['filename']}: {attachment['content']}")
