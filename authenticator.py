import json
import pyotp
import qrcode
import bcrypt
from behavior_monitor import BehaviorMonitor


class Authenticator:

    def __init__(self, login_file= "login.json"):

        self.login_file = login_file
        self.data = {}
        self.failed_attempts = {}
        self.behavior_monitor = BehaviorMonitor()

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
          self.increment_failed_attempts(username)
          return "Invalid credentials."

      self.behavior_monitor.get_geolocation()
      self.behavior_monitor.track_login(username)
      if self.behavior_monitor.is_suspicious(username):
          return "Suspicious login detected. Additional verification required."

      totp = pyotp.TOTP(user_data["key"])
      if not totp.verify(otp):
          self.increment_failed_attempts(username)
          return "Invalid OTP."

      return "Login successful."

    def increment_failed_attempts(self, username):

        if username not in self.failed_attempts:
            self.failed_attempts[username] = 0

        self.failed_attempts[username] += 1