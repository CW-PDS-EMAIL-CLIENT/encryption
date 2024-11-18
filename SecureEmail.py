import json
from DESCrypto import DESCrypto
from DigitalSignature import DigitalSignature


class SecureEmail:
    """Класс для обработки шифрования письма и добавления цифровой подписи."""

    @staticmethod
    def process_email(email_data, private_key_sign, public_key_sign, private_key_encrypt, public_key_encrypt):
        des_key = DESCrypto.generate_key()  # Генерация DES-ключа

        # Шифрование тела письма
        encrypted_body = DESCrypto.encrypt(email_data["body"], des_key)
        email_data["body"] = encrypted_body

        # Шифрование содержимого вложений
        for attachment in email_data["attachments"]:
            encrypted_content = DESCrypto.encrypt(attachment["content"], des_key)
            attachment["content"] = encrypted_content

        # Шифрование DES-ключа с использованием публичного ключа
        encrypted_des_key = DigitalSignature.encrypt_des_key(des_key, public_key_encrypt)

        # Подписание данных (тело письма + DES-ключ)
        signature = DigitalSignature.sign_data(email_data["body"]["encrypted_data"], des_key, private_key_sign)

        # Включение зашифрованного DES-ключа и подписи в тело письма
        email_data["body"]["encrypted_des_key"] = encrypted_des_key.hex()
        email_data["body"]["signature"] = signature.hex()

        return email_data

    @staticmethod
    def verify_email(email_data, private_key_encrypt, public_key_sign):
        encrypted_des_key = bytes.fromhex(email_data["body"]["encrypted_des_key"])
        signature = bytes.fromhex(email_data["body"]["signature"])

        # Расшифровка DES-ключа
        des_key = DigitalSignature.decrypt_des_key(encrypted_des_key, private_key_encrypt)

        # Проверка подписи
        is_valid = DigitalSignature.verify_signature(email_data["body"]["encrypted_data"], des_key, signature,
                                                     public_key_sign)
        if not is_valid:
            raise ValueError("Цифровая подпись недействительна.")

        # Расшифровка тела письма
        decrypted_body = DESCrypto.decrypt(email_data["body"]["encrypted_data"], email_data["body"]["iv"], des_key)
        email_data["body"] = decrypted_body

        # Расшифровка содержимого вложений
        for attachment in email_data["attachments"]:
            decrypted_content = DESCrypto.decrypt(attachment["content"]["encrypted_data"], attachment["content"]["iv"],
                                                  des_key)
            attachment["content"] = decrypted_content

        return email_data


if __name__ == "__main__":
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
    print("Decrypted Email:", json.dumps(processed_email, indent=4, ensure_ascii=False))
