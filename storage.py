import json
import base64
from cryption import Cryption

class Storage:

    def __init__(self, password_file="password.json"):

        self.data = {}
        self.password_file = password_file
        self.load_data()

    def load_data(self):
        try:
            with open(self.password_file, "r") as file:
                self.data = json.load(file)
        except FileNotFoundError:
            self.data = {}

    def store(self, email, password):

        encrypted_password = Cryption().encrypt(password)
        encrypted_password_base64 = base64.b64encode(encrypted_password).decode('utf-8')
        self.data[email] = encrypted_password_base64

        with open(self.password_file, "w") as file:
            json.dump(self.data, file, indent=4)


    def retrieve(self, email):

        if email in self.data:
            encrypted_password_base64 = self.data[email]
            encrypted_password = base64.b64decode(encrypted_password_base64.encode('utf-8'))
            return Cryption().decrypt(encrypted_password)
        else:
            raise KeyError(f"No password found for account: {email}")