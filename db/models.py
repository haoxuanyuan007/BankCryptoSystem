from extensions import db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import random


# This models.py link to the database, this also can demonstrate the structure of the database

def generate_account_number():
    return str(random.randint(1000000000, 9999999999))


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='client')
    account_number = db.Column(db.String(20), unique=True, nullable=False)
    balance = db.Column(db.Float, default=0.0)
    address = db.Column(db.Text, nullable=True)
    # HMAC
    address_integrity_hash = db.Column(db.String(64), nullable=True)
    contact = db.Column(db.Text, nullable=True)
    contact_integrity_hash = db.Column(db.String(64), nullable=True)
    # Key Version for data encryption
    key_version = db.Column(db.String(64), nullable=False, default='v1')
    # Key for digital signature
    # (Simulation, because in real life, the private to generate digital signature must store on user's device)
    private_key = db.Column(db.Text,
                            nullable=True)  # private key, should be encrypted and store on a hardware security module.
    public_key = db.Column(db.Text, nullable=True)  # normally should be in PEM format

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username} - Acct: {self.account_number}>"


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    amount = db.Column(db.Float, nullable=False)
    encrypted_details = db.Column(db.Text, nullable=False)
    # HMAC
    integrity_hash = db.Column(db.String(64), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='approved')
    key_version = db.Column(db.String(64), nullable=False, default='v1')
    signature = db.Column(db.Text, nullable=False)

    # Approved, Pending, Rejected

    def __repr__(self):
        return f"<Transaction {self.id} from {self.sender_id} to {self.receiver_id}, status: {self.status}>"


class KeyStore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    version = db.Column(db.String(64), unique=True, nullable=False)  # Can be date with number
    key_value = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_content = db.Column(db.Text, nullable=False)
    # HMAC
    integrity_hash = db.Column(db.String(64), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    key_version = db.Column(db.String(64), nullable=False, default='v1')
    signature = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f"<Message {self.id} from {self.sender_id} to {self.receiver_id}>"


class OperationLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    operation = db.Column(db.String(128), nullable=False)  # "Approve Transaction", "Update Account", etc.
    details = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<OperationLog {self.id} by Employee {self.employee_id}>"


class SystemConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(100), nullable=False)
