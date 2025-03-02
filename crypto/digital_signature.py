from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from crypto.encryption import aes_encrypt, aes_decrypt, get_key_by_version
from config import Config
import logging

logger = logging.getLogger(__name__)

def generate_user_keypair() -> (bytes, bytes):
    """
    Generating RSA keypair.
    """
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.public_key().export_key()
    return private_key, public_key

def encrypt_user_private_key(private_key: bytes) -> str:
    """
    Use current key to encrypt user private key.
    """
    current_key = Config.ENCRYPTION_KEY
    private_key_hex = private_key.hex()
    encrypted_bytes = aes_encrypt(private_key_hex, current_key)
    return encrypted_bytes.hex()

def decrypt_user_private_key(encrypted_private_key_hex: str, key_version: str) -> bytes:
    """
    Use current key to decrypt user private key.
    """
    key = get_key_by_version(key_version)
    encrypted_bytes = bytes.fromhex(encrypted_private_key_hex)
    decrypted_hex = aes_decrypt(encrypted_bytes, key)
    return bytes.fromhex(decrypted_hex)

def sign_data(plaintext: str, private_key_pem: bytes) -> str:
    """
    Use RSA private key to sign data, return hex string.
    """
    key = RSA.import_key(private_key_pem)
    h = SHA256.new(plaintext.encode('utf-8'))
    signature = pkcs1_15.new(key).sign(h)
    return signature.hex()

def verify_signature(plaintext: str, signature_hex: str, public_key_pem: bytes) -> bool:
    """
    Use RSA public key to verify signature.
    """
    try:
        h = SHA256.new(plaintext.encode('utf-8'))
        signature = bytes.fromhex(signature_hex)
        key_obj = RSA.import_key(public_key_pem)
        pkcs1_15.new(key_obj).verify(h, signature)
        return True
    except (ValueError, TypeError) as e:
        logger.error(f"Signature verification failed: {e}")
        return False