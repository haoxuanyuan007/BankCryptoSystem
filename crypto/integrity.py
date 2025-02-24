import hmac
import hashlib

def generate_hmac(data: str, key: str) -> str:
    """
    Generate HMAC for data.
    """
    return hmac.new(key.encode('utf-8'), data.encode('utf-8'), hashlib.sha256).hexdigest()

def verify_hmac(data: str, key: str, provided_hmac: str) -> bool:
    """
    Test if the data's HMAC match.
    """
    expected = generate_hmac(data, key)
    return hmac.compare_digest(expected, provided_hmac)