from DESCrypto import DESCrypto
from DigitalSignature import DigitalSignature
from Crypto.Random import get_random_bytes


class SecureEmail:
    """Класс для обработки шифрования письма и добавления цифровой подписи."""

    @staticmethod
    def process_email(email_data, private_key_sign, public_key_sign, private_key_encrypt, public_key_encrypt):
        des_key = DESCrypto.generate_key()  # Генерация DES-ключа
        iv = get_random_bytes(DESCrypto.DES_KEY_SIZE)  # Генерация IV

        # Шифрование текущего тела письма
        encrypted_content = DESCrypto.encrypt(email_data["body"], des_key, iv)

        # Шифрование содержимого вложений
        for attachment in email_data["attachments"]:
            attachment["content"] = DESCrypto.encrypt(attachment["content"], des_key, iv)

        # Шифрование DES-ключа с использованием публичного ключа
        encrypted_des_key = DigitalSignature.encrypt_des_key(des_key, public_key_encrypt)

        # Подписание данных (content + DES-ключ)
        signature = DigitalSignature.sign_data(encrypted_content, des_key, private_key_sign)

        # Формирование новой структуры тела письма
        email_data["body"] = {
            "iv": iv.hex(),
            "encrypted_des_key": encrypted_des_key.hex(),
            "signature": signature.hex(),
            "content": encrypted_content
        }

        return email_data

    @staticmethod
    def verify_email(email_data, private_key_encrypt, public_key_sign):
        body = email_data["body"]

        # Извлечение необходимых данных из тела письма
        iv = bytes.fromhex(body["iv"])
        encrypted_des_key = bytes.fromhex(body["encrypted_des_key"])
        signature = bytes.fromhex(body["signature"])
        encrypted_content = body["content"]

        # Расшифровка DES-ключа
        des_key = DigitalSignature.decrypt_des_key(encrypted_des_key, private_key_encrypt)

        # Проверка подписи
        is_valid = DigitalSignature.verify_signature(encrypted_content, des_key, signature, public_key_sign)
        if not is_valid:
            raise ValueError("Цифровая подпись недействительна.")

        # Расшифровка тела письма
        decrypted_content = DESCrypto.decrypt(encrypted_content, des_key, iv)
        email_data["body"]["content"] = decrypted_content

        # Расшифровка содержимого вложений
        for attachment in email_data["attachments"]:
            attachment["content"] = DESCrypto.decrypt(attachment["content"], des_key, iv)

        return email_data


# Пример использования SecureEmail
if __name__ == "__main__":
    import json

    email_data = {
        "to_email": "20egorka03@gmail.com",
        "subject": "Тестовое письмо",
        "body": "Это тестовое письмо, отправленное через SMTP.",
        "from_name": "Тест Отправитель",
        "to_name": "Тест Получатель",
        "attachments": [
            {"filename": "example_filename_1", "content": "attachment_content_1"},
            {"filename": "example_filename_2", "content": "attachment_content_2"},
        ],
    }

    # Генерация пар ключей для подписи и шифрования
    private_key_sign, public_key_sign = DigitalSignature.generate_keys()
    private_key_encrypt, public_key_encrypt = DigitalSignature.generate_keys()

    # Обработка письма
    processed_email = SecureEmail.process_email(email_data, private_key_sign, public_key_sign, private_key_encrypt,
                                                public_key_encrypt)
    print("Encrypted Email:", json.dumps(processed_email, indent=4, ensure_ascii=False))

    # Проверка и расшифровка письма
    verified_email = SecureEmail.verify_email(processed_email, private_key_encrypt, public_key_sign)
    print("Decrypted Email:", json.dumps(verified_email, indent=4, ensure_ascii=False))
