import base64
import json

import nacl.secret
import nacl.utils
import nacl.pwhash
import nacl.public


class Utils:
    def __init__(self, secret_key):
        self.SECRET_KEY = secret_key

    @staticmethod
    def encrypt_file(data, password):
        binary_data = data.encode()

        kdf = nacl.pwhash.argon2i.kdf

        # hardcoded salt (it can be loaded as ENV variable)
        salt = b'3\xba\x8f\r]\x1c\xcbOsU\x12\xb6\x9c(\xcb\x94'

        key = kdf(nacl.secret.SecretBox.KEY_SIZE, password.encode(), salt)
        box = nacl.secret.SecretBox(key)

        encrypted_data = box.encrypt(binary_data)

        return encrypted_data

    @staticmethod
    def decrypt(encrypted_data, password):
        kdf = nacl.pwhash.argon2i.kdf

        # hardcoded salt (it can be loaded as ENV variable)
        salt = b'3\xba\x8f\r]\x1c\xcbOsU\x12\xb6\x9c(\xcb\x94'

        key = kdf(nacl.secret.SecretBox.KEY_SIZE, password.encode(), salt)
        box = nacl.secret.SecretBox(key)

        decrypted_data = box.decrypt(encrypted_data)

        return decrypted_data

    def encrypt_message(self, message, client_public_key, safe_url=False):
        box = nacl.public.Box(self.SECRET_KEY, nacl.public.PublicKey(client_public_key))
        if not isinstance(message, bytes):
            if isinstance(message, dict):
                message = json.dumps(message)
            if isinstance(message, int):
                message = str(message)
        message = message.encode()
        encrypted_message = box.encrypt(message)
        if safe_url:
            return base64.urlsafe_b64encode(encrypted_message)
        return base64.b64encode(encrypted_message).decode()

    def decrypt_message(self, message, remote_public_key):
        box = nacl.public.Box(self.SECRET_KEY, nacl.public.PublicKey(remote_public_key))
        if not isinstance(message, bytes):
            message = message.encode()
        message = base64.b64decode(message)
        decrypted_message = box.decrypt(message)
        return decrypted_message.decode()
