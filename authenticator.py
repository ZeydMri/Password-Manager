import json
import os
import pyotp
import re
import bcrypt
from behavior_monitor import BehaviorMonitor
from email_services import EmailService


class Authenticator:

    def __init__(self, login_file= "login.json"):

        self.login_file = login_file
        self.failed_attempts = {}
        self.behavior_monitor = BehaviorMonitor()
        self.data = self.load_data()
        self.email_service = EmailService()

    def load_data(self):
        try:
            # Check if file exists and is not empty
            if not os.path.exists(self.login_file) or os.stat(self.login_file).st_size == 0:
                print("File is missing or empty. Returning empty data.")
                return {}

            # Attempt to read and parse the file
            with open(self.login_file, "r") as f:
                return json.load(f)

        except json.JSONDecodeError:
            print("Error: JSON file is corrupted. Returning empty data.")
            return {}

    def validate_email(self, email):

        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def register(self, email, password):

        print(f"Attempting to register email: {email}") # Debug

        if not self.validate_email(email):
            return "Invalid email format."
        print(f"self.validate_email: {email}") # Debug

        if email in self.data:
            return "E-mail already registered."
        print("email") # Debug

        self.email_service.send_registration_email(email)

        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        key = pyotp.random_base32()
        print(f"Generated TOTP Key: {key}") # Debug

        self.data[email] = {"password": hashed_password, "key": key}
        print("email") # Debug

        with open(self.login_file, "w") as f:
            json.dump(self.data, f, indent=4)

        tp = pyotp.totp.TOTP(key)
        uri = tp.provisioning_uri(name=email, issuer_name="SecureGuardian")
        print(f"Generated URI: {uri}")  # Debug
        return uri

    def login(self, email, password, otp):

      if email not in self.data:
          return "Account doesn't exist."

      user_data = self.data[email]
      if not bcrypt.checkpw(password.encode(), user_data["password"].encode()):
          self.increment_failed_attempts(email)
          return "Invalid credentials."

      self.behavior_monitor.get_geolocation()
      self.behavior_monitor.track_login(email)
      if self.behavior_monitor.is_suspicious(email):
          return "Suspicious login detected. Additional verification required."

      totp = pyotp.TOTP(user_data["key"])
      if not totp.verify(otp):
          self.increment_failed_attempts(email)
          return "Invalid OTP."

      return "Login successful."

    def increment_failed_attempts(self, email):

        if email not in self.failed_attempts:
            self.failed_attempts[email] = 0

        self.failed_attempts[email] += 1