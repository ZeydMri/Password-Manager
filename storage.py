import json
import cryption
from cryption import Cryption



class Storage:

    def __init__(self, username, password, password_file="password.json"):

        self.username = username
        self.data = {}
        self.password = password
        self.password_file = password_file

    def store(self, username, password):

        password = Cryption(password=self.password).encrypt()
        self.data[username] = password

        with open(self.password_file, "w") as f:
            json.dump(self.data, f)


    def retrieve(self, username):

        try:
            if username in self.password_file:
                with open(self.password_file, "r") as f:
                    return json.load(self.data[username], f)
        except FileNotFoundError:
            print("You don't have a password stored for this username")

