from Crypto.Hash import MD5


class MD5Hash:
    """Класс для генерации MD5 хэшей."""

    @staticmethod
    def generate_hash(data: str) -> str:
        """Генерация MD5 хэша для строки."""
        hash_object = MD5.new(data.encode())
        return hash_object.hexdigest()


# Тестирование MD5Hash
if __name__ == "__main__":
    test_data = "Пример123!@#Test"
    md5_hash = MD5Hash.generate_hash(test_data)
    print("MD5 Hash:", md5_hash)  # Ожидаемый вывод: хэш строки `test_data`
