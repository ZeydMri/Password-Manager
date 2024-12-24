import cryption
from cryption import Cryption



class Storage:

    def __init__(self, password, password_file="secrets.password"):
        self.password = password
        self.password_file = password_file

    def store(self):

        password = Cryption(password=self.password).encrypt()

        with open("secrets.password", "w") as password_file:
            password_file.write(password)

    def retrieve(self):

        try:
            with open("secrets.password", "r") as password_file:
                password_file.read()
        except FileNotFoundError:
            print("You don't have a password stored for this user name")

