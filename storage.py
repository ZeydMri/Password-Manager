import json
import base64
from cryption import Cryption

class Storage:
    """
    Manages secure storage and retrieval of encrypted passwords.

    This class provides a persistent storage system for encrypted passwords,
    organizing them by user email and account name. It handles the JSON
    file operations and works with the Cryption class to ensure passwords
    are always encrypted before storage and properly decrypted upon retrieval.

    Public Methods:
        store(user_email: str, account: str, password: str) -> None:
            Encrypts and stores a password for a specific user and account.

        retrieve(user_email: str, account: str) -> str:
            Retrieves and decrypts a password for a specific user and account.

        get_accounts_for_users(user_email: str) -> list:
            Returns a list of accounts for which a user has stored passwords.

    Attributes:
        data (dict): Nested dictionary storing encrypted passwords by user and account.
            Structure: {user_email: {account: encrypted_password}}
        password_file (str): Path to the JSON file storing encrypted passwords.

    Note:
        - Passwords are encrypted using the Cryption class before storage
        - Encrypted data is encoded in base64 for JSON compatibility

    """

    def __init__(self, password_file="password.json"):
        """
        Initialize the password storage system.

        Args:
            password_file (str, optional): Path to the JSON file for storing
                encrypted passwords. Defaults to "password.json".
        """

        self.data = {} # Initialize empty data dictionary
        self.password_file = password_file # Store path to password file
        self.load_data() # Load existing password data if available

    def load_data(self):
        """
        Load encrypted password data from JSON file.

        Attempts to read and parse the password file. If the file doesn't
        exist, initializes an empty data structure. This method is called
        automatically during initialization.

        Note:
            This is an internal method primarily used during initialization
            or when needing to refresh data from disk.
        """

        try:
            # Try to read and parse password file
            with open(self.password_file, "r") as file:
                self.data = json.load(file)
        except FileNotFoundError:
            # Initialize empty data if file doesn't exist
            self.data = {}

    def store(self, user_email, account, password):
        """
        Store an encrypted password for a user's account.

        This method encrypts the provided password using the Cryption class,
        encodes it in base64, and stores it in the JSON structure under the
        specified user email and account name.

        Args:
            user_email (str): Email address of the user.
            account (str): Name or identifier for the account.
            password (str): Plain text password to encrypt and store.

        Note:
            - The password is encrypted before storage
            - Overwrites any existing password for the same account
            - Changes are immediately written to disk

        """

        # Encrypt the password
        encrypted_password = Cryption().encrypt(password)

        # Convert encrypted bytes to base64 for JSON storage
        encrypted_password_base64 = base64.b64encode(encrypted_password).decode('utf-8')

        # Initialize user's password dictionary if needed
        if user_email not in self.data:
            self.data[user_email] = {}

        # Store encrypted password for the account
        self.data[user_email][account] = encrypted_password_base64

        # Save updated data to file
        with open(self.password_file, "w") as file:
            json.dump(self.data, file, indent=4)


    def retrieve(self, user_email, account):
        """
        Retrieve and decrypt a stored password.

        This method fetches an encrypted password from storage and decrypts
        it using the Cryption class.

        Args:
            user_email (str): Email address of the user.
            account (str): Name or identifier for the account.

        Returns:
            str: The decrypted password.

        Raises:
            KeyError: If no password is found for the specified account.
            ValueError: If decryption fails (from Cryption class).

        """

        # Check if account exists
        if account in self.data[user_email]:
            # Get encrypted password from storage
            encrypted_password_base64 = self.data[user_email][account]

            # Decode from base64 and decrypt
            encrypted_password = base64.b64decode(encrypted_password_base64.encode('utf-8'))
            return Cryption().decrypt(encrypted_password)
        else:
            raise KeyError(f"No password found for account: {account}")

    def get_accounts_for_users(self, user_email):
        """
        Get list of accounts with stored passwords for a user.

        Args:
            user_email (str): Email address of the user.

        Returns:
            list: List of account names that have stored passwords.
                Returns an empty list if user has no stored passwords.

        """

        # Return list of accounts or empty list if user has no stored passwords
        return list(self.data.get(user_email, {}).keys())

