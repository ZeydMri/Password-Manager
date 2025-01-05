import random
import string

class Generator:

    def __init__(self, password):
        self.password = password

    def generate_password(self, length=12):

        # Define characters to use in the password
        characters = string.ascii_letters + string.digits + string.punctuation

        # Generate a password by randomly electing characters
        self.password = ''.join(random.choice(characters) for i in range(length))

        return self.password