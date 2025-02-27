from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import os
import hmac
from hashlib import sha256
import datetime
MASTER_KEY_FILE = "master_key.txt"
ROTATION_TIME = 5




### Key Management ###
def generate_random_master_key() -> str:
    return os.urandom(16).hex()

def store_master_key(key: str, filepath: str = MASTER_KEY_FILE):
    with open(filepath, "w") as f:
        f.write(key)

def load_master_key(filepath: str = MASTER_KEY_FILE) -> str:
    if not os.path.exists(filepath):
        new_key = generate_random_master_key()
        store_master_key(new_key, filepath)
        return new_key
    with open(filepath, "r") as f:
        return f.read().strip()

def is_master_key_expired(filepath: str = MASTER_KEY_FILE, rotation_time: int = ROTATION_TIME) -> bool:
    if not os.path.exists(filepath):
        return True
    mtime = os.path.getmtime(filepath)
    last_modified = datetime.datetime.fromtimestamp(mtime)
    if datetime.datetime.now() - last_modified > datetime.timedelta(seconds=rotation_time):
        return True
    return False

def auto_rotate_master_key(filepath: str = MASTER_KEY_FILE, rotation_time: int = ROTATION_TIME) -> str:
    if is_master_key_expired(filepath, rotation_time):
        new_key = generate_random_master_key()
        store_master_key(new_key, filepath)
        return new_key
    else:
        return load_master_key(filepath)


### AES Symmetric Encryption ###
def aes_encrypt(plaintext: str, key: str) -> bytes:
    """
    Use AES-CBC mode to encrypt plaintext, return ciphertext including IV and ciphertext.
    key length need to be 16, 24 or 32 bytes (for AES-128, AES-192, AES-256).
    """
    # Convert key to byte
    aes_key = key.encode("utf-8") if isinstance(key, str) else key

    # Generate random iv, 16 byte length
    iv = os.urandom(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)

    # Pad the plaintext to fit the block size
    block_size = AES.block_size
    plaintext_bytes = plaintext.encode("utf-8")
    padding_length = block_size - (len(plaintext_bytes) % block_size)
    padded_plaintext = plaintext_bytes + bytes([padding_length] * padding_length)

    ciphertext = cipher.encrypt(padded_plaintext)
    return iv + ciphertext

def aes_decrypt(cipher_data: bytes, key: str) -> str:
    """
    Decrypt ciphertext, return plaintext.
    """
    aes_key = key.encode("utf-8") if isinstance(key, str) else key

    # First 16 bytes are ivs
    iv = cipher_data[:16]
    ciphertext = cipher_data[16:]

    # Get padded plaintext
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)

    # Remove PKCS7 padding
    padding_length = padded_plaintext[-1]
    plaintext_bytes = padded_plaintext[:-padding_length]

    return plaintext_bytes.decode("utf-8")


### RSA Asymmetric encryption ###
def generate_rsa_keypair(key_size: int = 2048):
    """
    Generate RSA keypair, return private key and public key in PEM (Privacy-Enhanced Mail) format.
    """
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.public_key().export_key()
    return private_key, public_key

def rsa_encrypt(plaintext: str, public_key_pem: str) -> bytes:
    """
    Use RSA to encrypt plaintext, return ciphertext.
    """
    public_key_pem = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(public_key_pem)
    ciphertext = cipher.encrypt(plaintext.encode("utf-8"))
    return ciphertext

def rsa_decrypt(ciphertext: bytes, private_key_pem: bytes) -> str:
    """
    Use RSA to decrypt ciphertext, return plaintext.
    """
    private_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(private_key)
    plaintext_bytes = cipher.decrypt(ciphertext)
    return plaintext_bytes.decode("utf-8")







