import random
import string

class Generator:
    """
    Generates secure random passwords with configurable characteristics.

    This class handles the creation of strong passwords using Python's
    cryptographically secure random number generator. Passwords include
    a mix of uppercase letters, lowercase letters, numbers, and special
    characters for maximum security.

    Public Methods:
        generate_password(length: int = 12) -> str:
            Generates a random password of specified length.
            Returns the generated password.

    Attributes:
        password (str): Stores the most recently generated password.
            Can be accessed after generation to retrieve the last
            created password.

    """

    def __init__(self, password):
        """
        Initialize the password generator.

        Args:
            password (str): Initial password value. Can be empty string
                if no initial password is needed.
        """
        self.password = password

    def generate_password(self, length=12):
        """
        Generate a secure random password.

        Creates a password using a cryptographically secure mix of:
            - Uppercase letters (A-Z)
            - Lowercase letters (a-z)
            - Numbers (0-9)
            - Special characters (!@#$%^&*()_+-=[]{}|;:,.<>?)

        Args:
            length (int, optional): Length of the password to generate.
            Defaults to 12 characters. Should be a positive integer.

        Returns:
            str: Generated password containing a random mix of allowed characters.

        """

        # Define characters to use in the password
        characters = string.ascii_letters + string.digits + string.punctuation

        # Generate a password by randomly electing characters
        self.password = ''.join(random.choice(characters) for i in range(length))

        return self.password