from binascii import Error

import grpc
from grpc import StatusCode
from concurrent import futures
from secureemail_pb2 import KeyGenerationResponse, EncryptedEmail, Email
from secureemail_pb2_grpc import SecureEmailServiceServicer, add_SecureEmailServiceServicer_to_server
from DigitalSignature import DigitalSignature
from DESCrypto import DESCrypto
from Crypto.Random import get_random_bytes
from SecureEmail import SecureEmail


class SecureEmailService(SecureEmailServiceServicer):
    def GenerateKeys(self, request, context):
        private_key_sign, public_key_sign = DigitalSignature.generate_keys()
        private_key_encrypt, public_key_encrypt = DigitalSignature.generate_keys()

        return KeyGenerationResponse(
            private_key_sign=private_key_sign,
            public_key_sign=public_key_sign,
            private_key_encrypt=private_key_encrypt,
            public_key_encrypt=public_key_encrypt
        )

    def ProcessEmail(self, request, context):
        email_body = request.email.email_body
        attachments = [{'filename': attachment.filename, 'content': attachment.content} for attachment in request.email.attachments]
        private_key_sign = request.private_key_sign
        public_key_encrypt = request.public_key_encrypt

        iv, encrypted_des_key, signature, encrypted_content, encrypted_attachments = SecureEmail.process_email(
            email_body, attachments, private_key_sign, public_key_encrypt)

        return EncryptedEmail(
            iv=iv,
            encrypted_des_key=encrypted_des_key,
            signature=signature,
            encrypted_content=encrypted_content,
            encrypted_attachments=encrypted_attachments
        )

    def VerifyEmail(self, request, context):
        iv = request.encrypted_email.iv
        encrypted_des_key = request.encrypted_email.encrypted_des_key
        signature = request.encrypted_email.signature
        encrypted_content = request.encrypted_email.encrypted_content
        encrypted_attachments = [{'filename': attachment.filename, 'content': attachment.content} for attachment in request.encrypted_email.encrypted_attachments]
        private_key_encrypt = request.private_key_encrypt
        public_key_sign = request.public_key_sign

        try:

            decrypted_content, decrypted_attachments = SecureEmail.verify_email(
                iv,
                encrypted_des_key,
                signature,
                encrypted_content,
                encrypted_attachments,
                private_key_encrypt,
                public_key_sign
            )

        except ValueError as e:
            context.set_code(StatusCode.INVALID_ARGUMENT)
            context.set_details(f"Invalid argument: {e}")
            return Email()  # Пустой ответ
        except Error as e:
            context.set_code(StatusCode.UNKNOWN)
            context.set_details(f"Unknown error: {e}")
            return Email()  # Пустой ответ

        return Email(
            email_body=decrypted_content,
            attachments=decrypted_attachments
        )

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    add_SecureEmailServiceServicer_to_server(SecureEmailService(), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    print("Server started at [::]:50051")
    server.wait_for_termination()


if __name__ == '__main__':
    serve()
