import json
from hashlib import md5
from DESCrypto import DESCrypto
from RSACrypto import RSACrypto


class SecureEmail:
    """Класс для шифрования email и добавления подписи."""

    @staticmethod
    def generate_signature(iv: str, encrypted_des_key: str, encrypted_md5: str) -> str:
        """Генерация цифровой подписи."""
        signature_data = f"{iv}:{encrypted_des_key}:{encrypted_md5}"
        return md5(signature_data.encode()).hexdigest()

    @staticmethod
    def secure_email(email_data: dict, rsa_keys_des: dict, rsa_keys_md5: dict) -> dict:
        """
        Шифрует email и добавляет подпись.

        :param email_data: Данные письма (структура JSON).
        :param rsa_keys_des: RSA-ключи для шифрования DES ключа.
        :param rsa_keys_md5: RSA-ключи для шифрования MD5 хэша.
        :return: Зашифрованная структура письма.
        """
        # 1. Генерация DES-ключа
        des_key = DESCrypto.generate_key()

        # 2. Шифрование тела письма (body)
        encrypted_body = DESCrypto.encrypt(email_data["body"], des_key)

        # 3. Создание MD5-хэша зашифрованного тела письма
        md5_hash = md5(encrypted_body["encrypted_data"].encode()).hexdigest()

        # 4. Шифрование DES-ключа и MD5-хэша с разными RSA ключами
        encrypted_des_key = RSACrypto.encrypt(des_key.hex(), rsa_keys_des["public_key"])
        encrypted_md5 = RSACrypto.encrypt(md5_hash, rsa_keys_md5["public_key"])

        # 5. Формирование цифровой подписи
        signature = SecureEmail.generate_signature(
            encrypted_body["iv"], encrypted_des_key, encrypted_md5
        )

        # 6. Обновление тела письма
        body_with_signature = {
            "content": encrypted_body["encrypted_data"],
            "signature": {
                "iv": encrypted_body["iv"],
                "encrypted_des_key": encrypted_des_key,
                "encrypted_md5": encrypted_md5,
                "signature": signature,
            },
        }

        # 7. Шифрование вложений
        encrypted_attachments = []
        for attachment in email_data["attachments"]:
            encrypted_content = DESCrypto.encrypt(attachment["content"], des_key)
            encrypted_attachments.append(
                {
                    "filename": attachment["filename"],
                    "content": encrypted_content["encrypted_data"],
                    "iv": encrypted_content["iv"],
                }
            )

        # 8. Формирование результирующего JSON
        secure_email_data = {
            "to_email": email_data["to_email"],
            "subject": email_data["subject"],
            "body": body_with_signature,  # Зашифрованное тело с подписью
            "from_name": email_data["from_name"],
            "to_name": email_data["to_name"],
            "attachments": encrypted_attachments,  # Зашифрованные вложения
        }

        return secure_email_data

    @staticmethod
    def verify_and_decrypt_email(
        encrypted_email: dict, rsa_keys_des: dict, rsa_keys_md5: dict
    ) -> dict:
        """
        Проверяет целостность и расшифровывает письмо.

        :param encrypted_email: Зашифрованное письмо.
        :param rsa_keys_des: RSA-ключи для расшифровки DES ключа.
        :param rsa_keys_md5: RSA-ключи для расшифровки MD5 хэша.
        :return: Расшифрованное письмо (структура JSON).
        """
        # 1. Извлечение подписанных данных из body
        body_signature = encrypted_email["body"]["signature"]

        # 2. Расшифровка DES-ключа
        des_key_hex = RSACrypto.decrypt(body_signature["encrypted_des_key"], rsa_keys_des["private_key"])
        des_key = bytes.fromhex(des_key_hex)

        # 3. Расшифровка MD5-хэша
        decrypted_md5 = RSACrypto.decrypt(body_signature["encrypted_md5"], rsa_keys_md5["private_key"])

        # 4. Проверка цифровой подписи
        recalculated_signature = SecureEmail.generate_signature(
            body_signature["iv"],
            body_signature["encrypted_des_key"],
            body_signature["encrypted_md5"],
        )
        if recalculated_signature != body_signature["signature"]:
            raise ValueError("Цифровая подпись не совпадает. Данные могут быть повреждены.")

        # 5. Проверка MD5-хэша
        recalculated_md5 = md5(encrypted_email["body"]["content"].encode()).hexdigest()
        if recalculated_md5 != decrypted_md5:
            raise ValueError("MD5-хэш не совпадает. Данные могут быть повреждены.")

        # 6. Расшифровка тела письма
        decrypted_body = DESCrypto.decrypt(
            encrypted_email["body"]["content"], body_signature["iv"], des_key
        )

        # 7. Расшифровка вложений
        decrypted_attachments = []
        for attachment in encrypted_email["attachments"]:
            decrypted_content = DESCrypto.decrypt(
                attachment["content"], attachment["iv"], des_key
            )
            decrypted_attachments.append(
                {"filename": attachment["filename"], "content": decrypted_content}
            )

        # 8. Формирование расшифрованного письма
        decrypted_email = {
            "to_email": encrypted_email["to_email"],
            "subject": encrypted_email["subject"],
            "body": decrypted_body,
            "from_name": encrypted_email["from_name"],
            "to_name": encrypted_email["to_name"],
            "attachments": decrypted_attachments,
        }

        return decrypted_email

# Тестирование
if __name__ == "__main__":
    # Оригинальное письмо
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

    # Генерация RSA-ключей для DES и MD5
    rsa_keys_des = RSACrypto.generate_keys()
    rsa_keys_md5 = RSACrypto.generate_keys()

    # Шифрование письма
    encrypted_email = SecureEmail.secure_email(email_data, rsa_keys_des, rsa_keys_md5)
    print("Encrypted Email:", json.dumps(encrypted_email, indent=4, ensure_ascii=False))

    # Расшифровка письма
    decrypted_email = SecureEmail.verify_and_decrypt_email(
        encrypted_email, rsa_keys_des, rsa_keys_md5
    )
    print("Decrypted Email:", json.dumps(decrypted_email, indent=4, ensure_ascii=False))
