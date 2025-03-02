from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import os
import datetime
from db.models import KeyStore, db
from crypto.integrity import generate_hmac
from db.models import SystemConfig


### Set Up and Logging to test or monitor key manage system ###
import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
# Log to terminal or write it in to file
handler = logging.StreamHandler()
# handler = logging.FileHandler('key_rotation.log')
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

### Key Management ###

# Rotation Cycle for update the key here using 5 second for testing, in real life can use days
ROTATION_TIME = 5

def get_rotation_time() -> int:
    """从数据库中获取轮换时间（转换为秒）。"""
    value_config = SystemConfig.query.filter_by(key="rotation_time_value").first()
    unit_config = SystemConfig.query.filter_by(key="rotation_time_unit").first()
    try:
        value = int(value_config.value) if value_config and value_config.value.isdigit() else 5
    except:
        value = 5
    unit = unit_config.value if unit_config else "seconds"
    multiplier = {"seconds": 1, "hours": 3600, "days": 86400}
    return value * multiplier.get(unit, 1)

def generate_random_master_key() -> str:
    return os.urandom(32).hex()

def get_latest_key() -> (str, str):
    """
    Return the newest key and its version.
    If there is no key in database, then generate a new key and store it.
    """
    latest_entry = KeyStore.query.order_by(KeyStore.created_at.desc()).first()
    if latest_entry:
        return latest_entry.key_value, latest_entry.version
    else:
        new_key = generate_random_master_key()
        new_version = datetime.datetime.now().isoformat()
        key_entry = KeyStore(version=new_version, key_value=new_key)
        db.session.add(key_entry)
        db.session.commit()
        return new_key, new_version

def is_master_key_expired(rotation_time: int = None) -> bool:
    """
    Check if the key is expired
    """
    if rotation_time is None:
        rotation_time = get_rotation_time()
    latest_entry = KeyStore.query.order_by(KeyStore.created_at.desc()).first()
    if not latest_entry:
        return True
    last_modified = latest_entry.created_at
    return datetime.datetime.now() - last_modified > datetime.timedelta(seconds=rotation_time)

def is_key_in_use(version: str) -> bool:
    """
    Check if there is still key_version in use on any data.
    """
    from db.models import Transaction, Message, User
    in_tx = Transaction.query.filter_by(key_version=version).first() is not None
    in_msg = Message.query.filter_by(key_version=version).first() is not None
    in_user = User.query.filter_by(key_version=version).first() is not None
    return in_tx or in_msg or in_user

def cleanup_old_keys(max_keys: int = 7):
    """
    Clean unused keys, but keep the key that is in use
    """
    keys = KeyStore.query.order_by(KeyStore.created_at.desc()).all()
    deleted_count = 0
    if len(keys) > max_keys:
        keys_to_check = keys[max_keys:]
        for key_entry in keys_to_check:
            if is_key_in_use(key_entry.version):
                logger.info(f"Key version {key_entry.version} is still in use, skipping deletion.")
            else:
                db.session.delete(key_entry)
                deleted_count += 1
        db.session.commit()
        logger.info(f"Cleaned up {deleted_count} old keys; retained keys in use or within latest {max_keys} keys.")
    else:
        logger.info("No old keys to clean up.")

def get_key_by_version(version: str) -> str:
    entry = KeyStore.query.filter_by(version=version).first()
    if not entry:
        raise ValueError(f"No key found for version {version}")
    return entry.key_value


### Function for reencrypt all the data ###
def reencrypt_data(encrypted_hex: str, old_version: str, new_version: str) -> (str, str):
    """
    Use old key and its version to decrypt the data,
    Use new key and its version to encrypt the data,
    Return encrypted hex string and new HMAC.
    """
    try:
        old_key = get_key_by_version(old_version)
    except ValueError as e:
        # If can't find old key, warning and return original data
        logger.error(f"No key found for version {old_version}: {e}")
        return encrypted_hex, None
    new_key = get_key_by_version(new_version)
    try:
        old_encrypted_bytes = bytes.fromhex(encrypted_hex)
    except Exception as e:
        logger.error(f"Error converting hex to bytes: {e}")
        return encrypted_hex, None
    try:
        plaintext = aes_decrypt(old_encrypted_bytes, old_key)
    except Exception as e:
        logger.error(f"Error during re-encryption (decryption failure) for version {old_version}: {e}")
        return encrypted_hex, None
    new_encrypted_bytes = aes_encrypt(plaintext, new_key)
    new_encrypted_hex = new_encrypted_bytes.hex()
    new_hmac = generate_hmac(new_encrypted_hex, new_key)
    return new_encrypted_hex, new_hmac

def reencrypt_data_records(old_version: str, new_version: str):
    """
    Reencrypt the data for Transaction and Message tables.
    Update encrypted_details/encrypted_content, HMAC and key_version.
    """
    from db.models import Transaction, Message
    txs = Transaction.query.filter_by(key_version=old_version).all()
    for tx in txs:
        new_encrypted_hex, new_hmac = reencrypt_data(tx.encrypted_details, old_version, new_version)
        # Only update when encryption successful
        if new_hmac is not None:
            tx.encrypted_details = new_encrypted_hex
            tx.integrity_hash = new_hmac
            tx.key_version = new_version

    msgs = Message.query.filter_by(key_version=old_version).all()
    for msg in msgs:
        new_encrypted_hex, new_hmac = reencrypt_data(msg.encrypted_content, old_version, new_version)
        if new_hmac is not None:
            msg.encrypted_content = new_encrypted_hex
            msg.integrity_hash = new_hmac
            msg.key_version = new_version


    db.session.commit()

def reencrypt_user_data(old_version: str, new_version: str):
    """
    Reencrypt the data about User.
    Update address, address_integrity_hash, contact, contact_integrity_hash and key_version。
    """
    from db.models import User
    usrs = User.query.filter_by(key_version=old_version).all()
    for usr in usrs:
        # Reencrypt address
        if usr.address:
            new_addr_hex, new_addr_hmac = reencrypt_data(usr.address, old_version, new_version)
            if new_addr_hmac is not None:
                usr.address = new_addr_hex
                usr.address_integrity_hash = new_addr_hmac

        # Reencrypt contact
        if usr.contact:
            new_contact_hex, new_contact_hmac = reencrypt_data(usr.contact, old_version, new_version)
            if new_contact_hmac is not None:
                usr.contact = new_contact_hex
                usr.contact_integrity_hash = new_contact_hmac

        if usr.private_key:
            new_priv_hex, new_priv_hmac = reencrypt_data(usr.private_key, old_version, new_version)
            if new_priv_hmac is not None:
                usr.private_key = new_priv_hex

        usr.key_version = new_version

    db.session.commit()


def auto_rotate_master_key(rotation_time: int = None) -> (str, str):
    """
    If the newest key is expired, generate new key, store it in KeyStore table (database),
    and then reencrypt all the data using the new key (Transactions, Messages, Users, ...).
    Return the new key and its version.
    This function must be invoked in application context.
    """
    from db.models import Transaction, Message, User  # Delayed imports to avoid circular dependencies
    if rotation_time is None:
        rotation_time = get_rotation_time()
    if is_master_key_expired(rotation_time):
        new_key = generate_random_master_key()
        new_version = datetime.datetime.now().isoformat()
        key_entry = KeyStore(version=new_version, key_value=new_key)
        db.session.add(key_entry)
        db.session.commit()

        # Reencrypt transactions data
        distinct_old_versions = db.session.query(Transaction.key_version)\
            .filter(Transaction.key_version != new_version).distinct().all()
        for (old_version,) in distinct_old_versions:
            try:
                reencrypt_data_records(old_version, new_version)
                logger.info(
                    f"Automatically re-encrypted Transaction records from version {old_version} to {new_version}")
            except Exception as e:
                logger.error(f"Error re-encrypting Transaction records from {old_version} to {new_version}: {e}")

        # Reencrypt message data
        distinct_old_message_versions = db.session.query(Message.key_version)\
            .filter(Message.key_version != new_version).distinct().all()
        for (old_version,) in distinct_old_message_versions:
            try:
                reencrypt_data_records(old_version, new_version)
                # print(f"Automatically re-encrypted Message records from version {old_version} to {new_version}")
                logger.info(f"Automatically re-encrypted Message records from version {old_version} to {new_version}")
            except Exception as e:
                # print(f"Error re-encrypting Message records from {old_version} to {new_version}: {e}")
                logger.error(f"Error re-encrypting Message records from {old_version} to {new_version}: {e}")

        # Reencrypt user data
        distinct_old_user_versions = db.session.query(User.key_version)\
            .filter(User.key_version != new_version).distinct().all()
        for (old_version,) in distinct_old_user_versions:
            try:
                reencrypt_user_data(old_version, new_version)
                # print(f"Automatically re-encrypted User data from version {old_version} to {new_version}")
                logger.info(f"Automatically re-encrypted User data from version {old_version} to {new_version}")
            except Exception as e:
                # print(f"Error re-encrypting User data from {old_version} to {new_version}: {e}")
                logger.error(f"Error re-encrypting User data from {old_version} to {new_version}: {e}")

        cleanup_old_keys(max_keys=7)
        return new_key, new_version
    else:
        return get_latest_key()




### AES Symmetric Encryption Functions ###
def aes_encrypt(plaintext: str, key: str) -> bytes:
    """
    AES Encryption, using cipher block chaining (CBC) mode.
    This will return cipher text in bytes and IV for decryption.
    """
    # Preprocess the input to avoid error, if key is 64 str in hex, convert to byte.
    if isinstance(key, str) and len(key) == 64:
        aes_key = bytes.fromhex(key)
    else:
        aes_key = key.encode("utf-8") if isinstance(key, str) else key

    iv = os.urandom(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    block_size = AES.block_size
    plaintext_bytes = plaintext.encode("utf-8")
    padding_length = block_size - (len(plaintext_bytes) % block_size)
    padded_plaintext = plaintext_bytes + bytes([padding_length] * padding_length)
    ciphertext = cipher.encrypt(padded_plaintext)
    return iv + ciphertext

def aes_decrypt(cipher_data: bytes, key: str) -> str:
    """
    AES Decryption, using cipher block chaining (CBC) mode.
    This will return plaintext in str.
    """
    # Preprocess the input to avoid error, if key is 64 str in hex, convert to byte.
    if isinstance(key, str) and len(key) == 64:
        aes_key = bytes.fromhex(key)
    else:
        aes_key = key.encode("utf-8") if isinstance(key, str) else key

    iv = cipher_data[:16]
    ciphertext = cipher_data[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    padding_length = padded_plaintext[-1]
    plaintext_bytes = padded_plaintext[:-padding_length]
    return plaintext_bytes.decode("utf-8")


### Asymmetric Encryption Functions ###
"""
NOTE: This is only a RSA implementation for demonstration purpose. These functions are not used in this project.
This project is using HTTPS: SSL/TLS protocol as an Asymmetric Encryption method to protect data in transit.
This project only use RSA key pair generating to implement Digital Signature.
"""
def generate_rsa_keypair(key_size: int = 2048):
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.public_key().export_key()
    return private_key, public_key

def rsa_encrypt(plaintext: str, public_key_pem: str) -> bytes:
    public_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(plaintext.encode("utf-8"))

def rsa_decrypt(ciphertext: bytes, private_key_pem: bytes) -> str:
    private_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(private_key)
    plaintext_bytes = cipher.decrypt(ciphertext)
    return plaintext_bytes.decode("utf-8")