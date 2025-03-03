import os
from dotenv import load_dotenv
from crypto.encryption import auto_rotate_master_key, get_latest_key

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "default_secret_key")
    SQLALCHEMY_DATABASE_URI = os.getenv("DB_URI")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    ENCRYPTION_KEY = None
    KEY_VERSION = None

def init_keys(app):
    with app.app_context():
        key, version = get_latest_key()
        if key is None:
            key, version = auto_rotate_master_key()

        app.config["ENCRYPTION_KEY"] = key
        app.config["KEY_VERSION"] = version
        Config.ENCRYPTION_KEY = key
        Config.KEY_VERSION = version