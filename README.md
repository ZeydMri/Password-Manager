# **SecureGuardian: Password Management System**
SecureGuardian is a full-featured, security-first password management application built with Python. The system combines modern cryptographic techniques, multi-factor authentication, and machine learning-based anomaly detection to provide a comprehensive solution for secure credential storage and management.

## **Key Features**
- Multi-Factor Authentication: Implements password hashing (bcrypt), Time-based OTP (pyotp), and QR code-based 2FA
- Machine Learning Security: Uses Isolation Forest algorithm to detect suspicious login attempts based on behavior patterns
- Industry standard Encryption: AES-256 encryption (via Fernet) with secure key management for password storage
- Intuitive GUI: User-friendly interface built with CustomTkinter framework
- Automated Security Alerts: Email notifications for suspicious activities and account verification
- Secure Password Generator: Built-in tool to create strong, unique passwords

## **System Architecture**
SecureGuardian follows object-oriented design principles with a modular architecture and proper separation of concerns:

- Authenticator: Manages user registration, login, and 2FA verification
- BehaviorMonitor: Tracks login patterns and detects anomalies using machine learning
- Cryption: Handles encryption and decryption of sensitive data
- Storage: Manages persistent storage of encrypted credentials
- EmailService: Handles security notifications and verification emails
- Generator: Creates secure random passwords
- PasswordManagerApp: Main application with GUI components

## **Technologies Used**

- Python: Core programming language
- CustomTkinter: Modern UI framework
- scikit-learn: Machine learning library for anomaly detection
- bcrypt: Secure password hashing
- cryptography.Fernet: Implementation of AES-256 symmetric encryption
- pyotp: Time-based one-time password library
- pandas: Data manipulation for the machine learning component
- qrcode: QR code generation for 2FA setup
- PIL: Image processing for UI components
- smtplib: Email communication for security alerts

## **Security Features In-Depth**

### **Multi-Layer Authentication**

SecureGuardian implements a defense-in-depth approach with multiple authentication factors:

- Knowledge factor (password) with bcrypt hashing and salt
- Possession factor (TOTP via authenticator app)
- Behavioral factor (login pattern analysis)

### **Anomaly Detection System**

The system monitors login patterns including:

- Time of day and day of week
- Geographic location
- IP address
- Failed attempt count
- Device information

Using Isolation Forest, it creates a model of normal user behavior and flags deviations that may indicate unauthorized access attempts.

### **Encryption Implementation**
All stored passwords are protected with AES-256 encryption:

- Encryption keys are generated and stored securely
- Encrypted data is encoded in base64 for JSON storage
- Key rotation capabilities built into the architecture
