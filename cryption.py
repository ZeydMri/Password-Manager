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

    #def encrypt(self, password):

        # Generates a key
        #self.key = Fernet.generate_key()
        # Saves the key in a file
        #with open("secrets.key", "wb") as key_file:
            #key_file.write(self.key)

        # Initialize a Fernet instance with the provided key to handle encryption and decryption
        #self.f = Fernet(self.key)
        # Encrypts the encoded password and generates a secure token
        #token = self.f.encrypt(password.encode())
        #return token

    #def decrypt(self, token):

        #with open("secrets.key", "rb") as key_file:
            self.key = key_file.read()

        #password = self.f.decrypt(token)








