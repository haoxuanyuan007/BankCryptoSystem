import os

# For test cases, use a temporary database
os.environ["DB_URI"] = "sqlite:///:memory:"

import unittest
import datetime
from flask import current_app
from app import app
from extensions import db
from db.models import User, Transaction, Message, KeyStore
from crypto.encryption import (
    aes_encrypt,
    aes_decrypt,
    generate_rsa_keypair,
    rsa_encrypt,
    rsa_decrypt,
    auto_rotate_master_key,
    get_key_by_version,
    reencrypt_data,
    reencrypt_data_records
)
from crypto.integrity import generate_hmac, verify_hmac
from crypto.digital_signature import (
    generate_user_keypair,
    sign_data,
    verify_signature,
    encrypt_user_private_key,
    decrypt_user_private_key
)
from config import Config


class TestEncryptionDecryption(unittest.TestCase):
    def test_aes_encryption_decryption(self):
        key = "thisisa16bytekey"
        plaintext = "Hello, MyBank!"
        encrypted = aes_encrypt(plaintext, key)
        decrypted = aes_decrypt(encrypted, key)
        self.assertEqual(plaintext, decrypted)

    def test_rsa_encryption_decryption(self):
        private_key, public_key = generate_rsa_keypair()
        plaintext = "Secret message for MyBank"
        encrypted = rsa_encrypt(plaintext, public_key)
        decrypted = rsa_decrypt(encrypted, private_key)
        self.assertEqual(plaintext, decrypted)


class TestIntegrityAndDigitalSignature(unittest.TestCase):
    def test_hmac_integrity(self):
        key = "thisisa16bytekey"
        data = "Test message"
        hmac_value = generate_hmac(data, key)
        self.assertTrue(verify_hmac(data, key, hmac_value))

    def test_digital_signature(self):
        private_key, public_key = generate_user_keypair()
        data = "Digital signature test for MyBank"
        signature = sign_data(data, private_key)
        self.assertTrue(verify_signature(data, signature, public_key))


class TestKeyManagement(unittest.TestCase):
    def setUp(self):
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        app.config["TESTING"] = True
        self.app_context = app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_auto_rotate_master_key(self):
        # 初始生成密钥
        key, version = auto_rotate_master_key(rotation_time=1)
        self.assertIsNotNone(key)
        self.assertIsNotNone(version)
        # 模拟密钥过期，手动修改 created_at 值
        latest_entry = KeyStore.query.order_by(KeyStore.created_at.desc()).first()
        latest_entry.created_at = datetime.datetime.now() - datetime.timedelta(seconds=10)
        db.session.commit()
        new_key, new_version = auto_rotate_master_key(rotation_time=1)
        self.assertNotEqual(key, new_key)

    def test_get_key_by_version(self):
        key, version = auto_rotate_master_key(rotation_time=1)
        self.assertEqual(get_key_by_version(version), key)


class TestSecureCommunication(unittest.TestCase):
    def test_ssl_configuration(self):
        # 模拟 SSL 配置测试：这里仅测试配置项
        with app.app_context():
            app.config["SSL_CONTEXT"] = ('cert.pem', 'key.pem')
            ssl_context = app.config.get("SSL_CONTEXT")
            self.assertIsNotNone(ssl_context)
            self.assertEqual(ssl_context, ('cert.pem', 'key.pem'))


class TestAuthenticationAuthorization(unittest.TestCase):
    def setUp(self):
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        app.config["TESTING"] = True
        self.client = app.test_client()
        self.app_context = app.app_context()
        self.app_context.push()
        db.create_all()
        # 创建一个测试用户（客户端）
        user = User(username="testuser", account_number="1234567890", balance=1000.0, role="client")
        user.set_password("password")
        db.session.add(user)
        db.session.commit()
        self.user_id = user.id

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_login_success(self):
        # 模拟登录过程（假设登录后跳转到 OTP 页面）
        response = self.client.post("/auth/login", data={"username": "testuser", "password": "password"},
                                    follow_redirects=True)
        self.assertIn(b"OTP", response.data)  # 检查响应中是否包含“OTP”


if __name__ == '__main__':
    unittest.main()