import os
from dotenv import load_dotenv
from crypto.encryption import auto_rotate_master_key

load_dotenv()


class Config:
    """
    Configuration for Database and Keys for encryption.
    """
    SECRET_KEY = os.getenv("SECRET_KEY", "default_secret_key")

    # Key stored in env variable, not auto rotate
    ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "default_encryption_key")

    # Key stored in master_key.txt, auto rotating all the time
    # ENCRYPTION_KEY = auto_rotate_master_key()

    # MySQL
    SQLALCHEMY_DATABASE_URI = os.getenv("DB_URI")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
