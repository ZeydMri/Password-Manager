import json
import os
import pyotp
import re
import bcrypt
from behavior_monitor import BehaviorMonitor
from email_services import EmailService


class Authenticator:
    """
        Handles user authentication, registration, and security monitoring.

        This class manages user credentials, two-factor authentication, and monitors
        login attempts for suspicious activity. It uses bcrypt for password hashing
        and TOTP for 2FA.

        Public Methods:
            register(email: str, password: str) -> str:
                Registers new user and returns 2FA QR code URI.

            login(email: str, password: str, otp: str) -> str:
                Authenticates user login with 2FA verification.

            validate_email(email: str) -> bool:
                Validates email format.

        Attributes:
            login_file (str): Path to the JSON file storing user credentials.
            failed_attempts (dict): Tracks number of failed login attempts per user.
            data (dict): User credentials and 2FA keys.
            behavior_monitor (BehaviorMonitor): Monitors for suspicious login activity.
            email_service (EmailService): Handles email notifications.
    """

    def __init__(self, login_file= "login.json"):
        """
        Initialize authenticator with user credentials file and monitoring systems

        Args:
            login_file (str): Path to the JSON file storing user credentials (default: "login.json")
        """

        self.login_file = login_file # File storing user credentials
        self.failed_attempts = self.load_failed_attempts() # Load the history of failed login attempts for security monitoring
        self.behavior_monitor = BehaviorMonitor() # Monitor for suspicious activity
        self.data = self.load_data() # Load user data
        self.email_service = EmailService() # Service for sending emails

    def load_failed_attempts(self):
        """
        Load the history of failed login attempts from JSON file

        Returns:
            dict: A dictionary mapping email addresses to number of failed attempts
                  Returns empty dict if file doesn't exist or is corrupted
        """

        try:
            # Try to open and read the failed attempts file
            with open("failed_attempts.json", "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            # Return empty dict if file doesn't exist or is corrupted
            return {}

    def save_failed_attempts(self):
        """
        Save failed login attempts to JSON file
        This is called after any changes to the failed attempts count
        """

        # Write the current failed attempts data to file
        with open("failed_attempts.json", "w") as f:
            json.dump(self.failed_attempts, f)

    def increment_failed_attempts(self, email):
        """
        Increment the failed login attempt counter for a specific email
        Used for security monitoring and potential account lockout

        Args:
            email (str): The email address to track
        """

        # Initialize counter if email not previously tracked
        if email not in self.failed_attempts:
            self.failed_attempts[email] = 0

        # Increment the failed attempts counter
        self.failed_attempts[email] += 1

        # Save updated data to file
        self.save_failed_attempts()

    def reset_failed_attempts(self, email):
        """
        Reset the failed attempts counter after successful login

        Args:
            email (str): The email address to reset
        """

        if email in self.failed_attempts:
            # Reset counter to 0 and save to file
            self.failed_attempts[email] = 0
            self.save_failed_attempts()

    def load_data(self):
        """
        Load user credentials and data from the login file
        Includes error handling for missing or corrupted files

        Returns:
                dict: Dictionary containing user data, or empty dict if file is invalid
        """

        try:
            # Check if file exists and is not empty
            if not os.path.exists(self.login_file) or os.stat(self.login_file).st_size == 0:
                print("File is missing or empty. Returning empty data.")
                return {}

            # Read and parse the JSON file
            with open(self.login_file, "r") as f:
                return json.load(f)

        except json.JSONDecodeError:
            print("Error: JSON file is corrupted. Returning empty data.")
            return {}

    def validate_email(self, email):
        """
        Validate email format using regex pattern
        Args:
            email (str): Email address to validate
        Returns:
                bool: True if email format is valid, False otherwise
        """

        # Regex pattern for email validation:
        # - Allows alphanumeric characters, dots, underscores, percent, plus, and hyphen in local part
        # - Requires @ symbol
        # - Allows alphanumeric characters, dots, and hyphens in domain
        # - Requires domain extension of 2 or more characters
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def register(self, email, password):
        """
        Register a new user with email and password
        Sets up 2FA and returns QR code URI for authenticator app

        Args:
            email (str): User's email address
            password (str): User's chosen password

        Returns:
                str: Either error message or QR code URI for 2FA setup
        """

        # Validate email format
        if not self.validate_email(email):
            return "Invalid email format."

        # Check if email is already registered
        if email in self.data:
            return "E-mail already registered."

        # Send welcome email to new user
        self.email_service.send_registration_email(email)

        # Hash the password using bcrypt with a random salt
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        # Generate random key for 2FA
        key = pyotp.random_base32()

        # Store user data
        self.data[email] = {
            "password": hashed_password,
            "key": key
        }

        # Save updated user data to file
        with open(self.login_file, "w") as f:
            json.dump(self.data, f, indent=4)

        # Generate QR code URI for authenticator app setup
        tp = pyotp.totp.TOTP(key)
        uri = tp.provisioning_uri(name=email, issuer_name="SecureGuardian")

        return uri

    def login(self, email, password, otp):
        """
        Authenticate user login with email, password and 2FA code
        Includes behavior monitoring and suspicious activity detection

        Args:
            email (str): User's email address
            password (str): User's password
            otp (str): One-time password from authenticator app

        Returns:
                str: Status message indicating login result
        """

        # Check if account exists
        if email not in self.data:
            return "Account doesn't exist."

        # Get user data
        user_data = self.data[email]

        # Verify password using bcrypt
        if not bcrypt.checkpw(password.encode(), user_data["password"].encode()):
            self.increment_failed_attempts(email)
            return "Invalid credentials."

        # Get user's geolocation for behavior monitoring
        self.behavior_monitor.get_geolocation()

        # Track this login attempt and check for suspicious patterns
        self.behavior_monitor.track_login(email, self.failed_attempts.get(email, 0))

        # Reset failed attempts counter on successful password verification
        self.reset_failed_attempts(email)

        # Check if login attempt is suspicious based on behavior patterns
        if self.behavior_monitor.is_suspicious(email):
            return "Suspicious login detected. Additional verification required."

        # Verify 2FA code
        totp = pyotp.TOTP(user_data["key"])
        if not totp.verify(otp):
            self.increment_failed_attempts(email)
            return "Invalid OTP."

        return "Login successful."