import json
import pyotp
import qrcode
import bcrypt


class Authenticator:

    def __init__(self, username, password, login_file= "login.json"):

        self.username = username
        self.password = password
        self.login_file = login_file
        self.data = {}

    def register(self, username, password):

        if username in self.data:
            return "Username already exists."

        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        key = pyotp.random_base32()

        self.data[username] = {"password": hashed_password, "key": key}

        with open(self.login_file, "w") as f:
            json.dump(self.data, f)

        totp = pyotp.TOTP(key)
        return totp.provisioning_uri(name=username, issuer_name="SecretGuardian")

    def login(self, username, password, otp):

      if username not in self.data:
          return "Account doesn't exist."

      user_data = self.data[username]
      if not bcrypt.checkpw(password.encode(), user_data["password"].encode()):
          return "Invalid credentials."

      totp = pyotp.TOTP(user_data["key"])
      if not totp.verify(otp):
          return "Invalid OTP."

      return "Login successful."




