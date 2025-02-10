import cryptography.fernet
from cryptography.fernet import Fernet


class Cryption:
    """
    Handles symmetric encryption and decryption of passwords.

    This class manages encryption keys and provides methods for secure
    password encryption and decryption using the Fernet symmetric encryption
    scheme. It automatically handles key generation and persistence,
    ensuring the same key is used across sessions.

    Public Methods:
        encrypt(password: str) -> bytes:
            Encrypts a password string and returns encrypted bytes.

        decrypt(token: bytes) -> str:
            Decrypts an encrypted password token and returns original string.

    Attributes:
        key_file (str): Path to file storing the encryption key.
        key (bytes): The Fernet encryption key.
        f (Fernet): Fernet cipher instance for encryption/decryption.

    """

    def __init__(self, key_file="secrets.key"):
        """
        Initialize the encryption system.

        Args:
            key_file (str, optional): Path to the encryption key file.
                Defaults to "secrets.key" in the current directory.
        """

        self.key_file = key_file
        self.key = self._load_or_generate_key() # Load existing key or generate a new one
        self.f = Fernet(self.key) # Initialize Fernet cipher with the key

    def _load_or_generate_key(self):
        """
        Load existing encryption key or generate a new one.

        This method attempts to load an existing encryption key from
        the key file. If the file doesn't exist, it generates a new
        key and saves it to the file.

        Returns:
            bytes: The encryption key, either loaded or newly generated.

        Note:
            This is a private method used internally by the class.
            It should not be called directly by users of the class.

        """

        # Try to load existing key
        try:
            with open("secrets.key", "rb") as key_file:
                return key_file.read()
        except FileNotFoundError:
            # Generate new key if file doesn't exist
            key = Fernet.generate_key()

            # Save the new key
            with open("secrets.key", "wb") as key_file:
                key_file.write(key)
                return key

    def encrypt(self, password):
        """
        Encrypt a password using Fernet symmetric encryption.

        This method takes a plaintext password string, encodes it to bytes,
        and encrypts it using the Fernet cipher.

        Args:
            password (str): The plaintext password to encrypt.

        Returns:
            bytes: The encrypted password token.

        """

        # Convert password to bytes and encrypt
        token = password.encode()
        return self.f.encrypt(token)

    def decrypt(self, token):
        """
        Decrypt a password token.

        This method takes an encrypted password token and attempts to
        decrypt it using the Fernet cipher.

        Args:
            token (bytes): The encrypted password token to decrypt.

        Returns:
            str: The decrypted password string.

        Raises:
            ValueError: If the token is invalid or decryption fails.
                This can happen if the token was corrupted or if it
                was encrypted with a different key.

        """

        try:
            # Attempt to decrypt and convert back to string
            return self.f.decrypt(token).decode()
        except cryptography.fernet.InvalidToken:
            # Handle invalid or corrupted tokens
            raise ValueError("Invalid token! Decryption failed.")
        except Exception as e:
            # Handle any other decryption errors
            raise ValueError(f"Decryption failed: {e}")