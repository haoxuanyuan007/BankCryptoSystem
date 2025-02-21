import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "default_secret_key")
    ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "default_encryption_key")

    # MySQL
    SQLALCHEMY_DATABASE_URI = os.getenv("DB_URI", "mysql+pymysql://user:password@localhost/mybankdb")
    SQLALCHEMY_TRACK_MODIFICATIONS = False