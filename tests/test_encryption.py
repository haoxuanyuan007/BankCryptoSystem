import unittest
from crypto.encryption import aes_encrypt, aes_decrypt, generate_rsa_keypair, rsa_encrypt, rsa_decrypt

"""
This is a test script I wrote for testing the functionality for both AES and RSA encryption.
To run this test script, in command prompt, navigate (cd) to root directory "MyBankCryptoSystem",
and run "python -m unittest tests/test_encryption.py"

For each encryption and decryption testing, there will be givien example keys and original text (plaintext or ciphertext).
Using these data to perform encryption and decryption, then compare the result of decrypted and original text.
When the encryption algorithms are fully functional, the result of decrypted and original text should be the same,
the test script should return something like this:

"Ran 2 tests in 0.177s"
"OK"
"""

class TestAESEncryption(unittest.TestCase):
    def test_aes_encrypt_decrypt(self):
        key = "thisisa16bytekey"
        original_text = "Hello, MyBank!"
        encrypted = aes_encrypt(original_text, key)
        decrypted = aes_decrypt(encrypted, key)
        self.assertEqual(decrypted, original_text)

class TestRSAEncryption(unittest.TestCase):
    def test_rsa_encrypt_decrypt(self):
        private_key, public_key = generate_rsa_keypair()
        original_text = "Confidential Message for MyBank"
        encrypted = rsa_encrypt(original_text, public_key)
        decrypted = rsa_decrypt(encrypted, private_key)
        self.assertEqual(decrypted, original_text)

if __name__ == '__main__':
    unittest.main()
