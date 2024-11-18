from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import MD5
from Crypto.Random import get_random_bytes

# Генерация пары ключей (приватного и публичного)
def generate_keys():
    key = RSA.generate(2048)  # Генерация 2048-битного RSA ключа
    private_key = key.export_key()  # Приватный ключ
    public_key = key.publickey().export_key()  # Публичный ключ
    return private_key, public_key

# Подписание сообщения
def sign_message(message, private_key):
    key = RSA.import_key(private_key)  # Импорт приватного ключа
    h = MD5.new(message.encode())  # Хэширование сообщения
    signer = pkcs1_15.new(key)  # Создание подписанта
    signature = signer.sign(h)  # Подписание хэша
    return signature

# Проверка подписи
def verify_signature(message, signature, public_key):
    key = RSA.import_key(public_key)  # Импорт публичного ключа
    h = MD5.new(message.encode())  # Хэширование сообщения
    verifier = pkcs1_15.new(key)  # Создание проверяющего
    try:
        verifier.verify(h, signature)  # Проверка подписи
        return True  # Подпись действительна
    except (ValueError, TypeError):
        return False  # Подпись недействительна

# Генерация ключей
private_key, public_key = generate_keys()

# Сообщение, которое будет подписано
message = "This is a secret message."

# Подписание сообщения
signature = sign_message(message, private_key)
print(f"Signature: {signature.hex()}")

# Проверка подписи
is_valid = verify_signature(message, signature, public_key)
print(f"Signature valid: {is_valid}")
