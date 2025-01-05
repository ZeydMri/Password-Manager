import cryptography.fernet
from cryptography.fernet import Fernet


class Cryption:

    def __init__(self, password, key_file="secrets.key"):
        self.password = password
        self.key_file = key_file
        self.key = self._load_or_generate_key()
        self.f = Fernet(self.key)

    def _load_or_generate_key(self):
        try:
            with open("secrets.key", "rb") as key_file:
                return key_file.read()
        except FileNotFoundError:
            key = Fernet.generate_key()
            with open("secrets.key", "wb") as key_file:
                key_file.write(key)
                return key

    def encrypt(self):
        token = self.password.encode()
        return self.f.encrypt(token)

    def decrypt(self, token):
        try:
            return self.f.decrypt(token).decode()
        except cryptography.fernet.InvalidToken:
            raise ValueError("Invalid token! Decryption failed.")
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")