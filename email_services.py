import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from datetime import datetime

class EmailService:
    """
        Manages secure email communications for the password manager.

        This class handles the composition and sending of various types of
        security-related emails, including welcome messages, suspicious login
        alerts, and verification codes. All emails are sent using SMTP with
        TLS encryption.

        Public Methods:
            send_registration_email(user_email: str) -> bool:
                Sends welcome email to newly registered users with security tips.

            send_suspicious_login_alert(user_email: str, login_data: dict) -> bool:
                Sends alert when suspicious login activity is detected.

            send_verification_code(user_email: str, verification_code: str) -> bool:
                Sends verification code for additional authentication.

        Attributes:
            smtp_server (str): SMTP server address (defaults to Gmail).
            smtp_port (int): SMTP server port for TLS.
            sender_email (str): Email address from environment variable.
            sender_password (str): Email password from environment variable.

        Environment Variables Required:
            EMAIL_SENDER: Email address used to send messages
            EMAIL_PASSWORD: Password for the sender email account

        Note:
            All methods return False if email configuration is missing or
            if sending fails for any reason.

        """

    def __init__(self):
        """
        Initialize email service with SMTP configuration.

        Loads email credentials from environment variables.
        Uses Gmail's SMTP server by default with TLS encryption.

        """

        # SMTP server configuration
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 587 # Port for TLS

        # Get credentials from environment variables
        self.sender_email = os.getenv("EMAIL_SENDER")
        self.sender_password = os.getenv("EMAIL_PASSWORD")

    def send_registration_email(self, user_email):
        """
        Send welcome email to newly registered users.

        Sends a welcome message with important security tips and
        best practices for using the password manager.

        Args:
            user_email (str): Recipient's email address.

        Returns:
            bool: True if email sent successfully, False otherwise.

        """

        # Verify if email configuration exists
        if not self.sender_email or not self.sender_password:
            print("Email configuration not set. Please set environment variables.")
            return False

        try:
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = user_email
            msg['Subject'] = "Welcome to SecureGuardian Password Manager"

            # Compose email body with security tips
            body = f"""
Welcome to SecureGuardian Password Manager!

Thank you for registering with us. Your account has been successfully created.

Important Security Tips:
    1. Keep your 2FA device secure
    2. Never share your passwords
    3. Use strong, unique passwords for each account
    4. Regularly update your passwords

If you didn't create this account, please contact us immediately.

Best regards,
The SecureGuardian Team
            """

            msg.attach(MIMEText(body, 'plain'))

            # Send email using SMTP with TLS
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()  # Enable TLS encryption
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)

            print(f"Registration email sent successfully to {user_email}")
            return True

        except Exception as e:
            print(f"Failed to send registration email: {str(e)}")
            return False

    def send_suspicious_login_alert(self, user_email, login_data):
        """
        Send alert email for suspicious login activity.

        Notifies user of potentially unauthorized login attempts with
        detailed information about the attempt and security recommendations.

        Args:
            user_email (str): User's email address.
            login_data (dict): Dictionary containing login attempt details:
                - login_time (str): ISO format timestamp
                - city (str): City of login attempt
                - country (str): Country of login attempt
                - ip_adress (str): IP address of login attempt

        Returns:
            bool: True if alert sent successfully, False otherwise.

        """


        if not self.sender_email or not self.sender_password:
            print("Email configuration not set. Please set environment variables.")
            return False

        try:
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = user_email
            msg['Subject'] = "⚠️ Suspicious Login Activity Detected"

            # Format timestamp for readability
            login_time = datetime.fromisoformat(login_data['login_time']).strftime("%B %d, %Y at %I:%M %p")

            # Compose detailed alert message
            body = f"""
            ⚠️ SECURITY ALERT ⚠️

We detected a suspicious login attempt to your SecureGuardian account.

Login Details:
    - Time: {login_time}
    - Location: {login_data['city']}, {login_data['country']}
    - IP Address: {login_data['ip_adress']}
    - Device/Browser: {login_data.get('user_agent', 'Unknown')}

If this was you:
    - Ignore this message
    - Consider marking this location as trusted in your account settings

If this wasn't you:
    1. Change your password immediately
    2. Enable additional security measures
    3. Review your recent account activity
    4. Contact our support team if you notice any unauthorized changes

Security Tips:
    - Use a strong, unique password
    - Enable two-factor authentication if not already enabled
    - Regularly monitor your account for suspicious activity
    - Never share your login credentials

If you need assistance or have questions, please contact our support team immediately.

Stay secure,
The SecureGuardian Security Team

Note: This is an automated security alert. Please do not reply to this email.
            """

            msg.attach(MIMEText(body, 'plain'))

            # Send alert via SMTP with TLS
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)

            print(f"Suspicious login alert sent successfully to {user_email}")
            return True

        except Exception as e:
            print(f"Failed to send suspicious login alert: {str(e)}")
            return False

    def send_verification_code(self, user_email, verification_code):
        """
        Send verification code for additional authentication.

        Sends a time-sensitive verification code when additional
        authentication is required, such as during suspicious login attempts.

        Args:
            user_email (str): User's email address.
            verification_code (str): Generated verification code.

        Returns:
            bool: True if code sent successfully, False otherwise.

        Note:
            Verification codes expire after 10 minutes for security purposes.

        """

        if not self.sender_email or not self.sender_password:
            print("Email configuration not set. Please set environment variables.")
            return False

        try:
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = user_email
            msg['Subject'] = "SecureGuardian - Verify Your Login"

            body = f"""
SecureGuardian Security Verification

A login attempt requires additional verification.

Your verification code is: {verification_code}

If you did not attempt to log in, please:
    1. Change your password immediately
    2. Enable two-factor authentication if not already enabled
    3. Contact support for assistance

This code will expire in 10 minutes.

Best regards,
The SecureGuardian Security Team
            """

            msg.attach(MIMEText(body, 'plain'))

            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)

            print(f"Verification code sent successfully to {user_email}")
            return True

        except Exception as e:
            print(f"Failed to send verification code: {str(e)}")
            return False
