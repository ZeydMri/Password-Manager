import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from datetime import datetime

class EmailService:
    def __init__(self):
        # Email configuration - should be set as environment variables
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 587
        self.sender_email = os.getenv("EMAIL_SENDER")  # Your Gmail address
        self.sender_password = os.getenv("EMAIL_PASSWORD")  # Your App Password

    def send_registration_email(self, user_email):
        if not self.sender_email or not self.sender_password:
            print("Email configuration not set. Please set environment variables.")
            return False

        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = user_email
            msg['Subject'] = "Welcome to SecretGuardian Password Manager"

            # Create email body
            body = f"""
Welcome to SecretGuardian Password Manager!

Thank you for registering with us. Your account has been successfully created.

Important Security Tips:
    1. Keep your 2FA device secure
    2. Never share your passwords
    3. Use strong, unique passwords for each account
    4. Regularly update your passwords

If you didn't create this account, please contact us immediately.

Best regards,
The SecretGuardian Team
            """

            msg.attach(MIMEText(body, 'plain'))

            # Create SMTP session
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()  # Enable TLS
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)

            print(f"Registration email sent successfully to {user_email}")
            return True

        except Exception as e:
            print(f"Failed to send registration email: {str(e)}")
            return False

    def send_suspicious_login_alert(self, user_email, login_data):
        if not self.sender_email or not self.sender_password:
            print("Email configuration not set. Please set environment variables.")
            return False

        try:
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = user_email
            msg['Subject'] = "⚠️ Suspicious Login Activity Detected"

            # Format the login time nicely
            login_time = datetime.fromisoformat(login_data['login_time']).strftime("%B %d, %Y at %I:%M %p")

            body = f"""
            ⚠️ SECURITY ALERT ⚠️

We detected a suspicious login attempt to your SecretGuardian account.

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
The SecretGuardian Security Team

Note: This is an automated security alert. Please do not reply to this email.
            """

            msg.attach(MIMEText(body, 'plain'))

            # Create SMTP session and send email
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
        Send a verification code to the user's email for suspicious login verification.

        Args:
            user_email (str): The recipient's email address
            verification_code (str): The verification code to be sent

        Returns:
            bool: True if email was sent successfully, False otherwise
        """
        if not self.sender_email or not self.sender_password:
            print("Email configuration not set. Please set environment variables.")
            return False

        try:
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = user_email
            msg['Subject'] = "SecretGuardian - Verify Your Login"

            body = f"""
SecretGuardian Security Verification

A login attempt requires additional verification.

Your verification code is: {verification_code}

If you did not attempt to log in, please:
    1. Change your password immediately
    2. Enable two-factor authentication if not already enabled
    3. Contact support for assistance

This code will expire in 10 minutes.

Best regards,
The SecretGuardian Security Team
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
