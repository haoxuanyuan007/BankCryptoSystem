# transaction.py:
from flask import Blueprint, request, render_template, redirect, url_for, flash, session
from extensions import db
from db.models import Transaction, User
from crypto.encryption import aes_encrypt, aes_decrypt, get_key_by_version
from config import Config
from crypto.integrity import generate_hmac, verify_hmac
from crypto.digital_signature import sign_data, decrypt_user_private_key, verify_signature

transaction_bp = Blueprint('transaction', __name__)


@transaction_bp.route('/new', methods=['GET', 'POST'])
def new_transaction():
    if 'user_id' not in session:
        flash("Please log in to initiate a transaction.")
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        receiver_input = request.form.get('receiver')
        amount_str = request.form.get('amount')
        details = request.form.get('details')
        signature = None

        if not receiver_input or not amount_str or not details:
            flash("All fields are required!")
            return redirect(url_for('transaction.new_transaction'))

        try:
            amount = float(amount_str)
        except ValueError:
            flash("Invalid amount!")
            return redirect(url_for('transaction.new_transaction'))

        if amount <= 0:
            flash("Amount must be greater than 0!")
            return redirect(url_for('transaction.new_transaction'))

        sender_id = session['user_id']
        sender = User.query.get(sender_id)
        if not sender:
            flash("Sender not found.")
            return redirect(url_for('transaction.new_transaction'))

        receiver = User.query.filter_by(account_number=receiver_input).first()
        if not receiver:
            receiver = User.query.filter_by(username=receiver_input).first()
        if not receiver:
            flash("Receiver not found.")
            return redirect(url_for('transaction.new_transaction'))

        # Get current key version and key
        encryption_key = Config.ENCRYPTION_KEY
        print("Encryption Key:", encryption_key)
        current_version = Config.KEY_VERSION
        print("Current Key Version:", current_version)

        encrypted_bytes = aes_encrypt(details, encryption_key)
        encrypted_details = encrypted_bytes.hex()
        integrity = generate_hmac(encrypted_details, encryption_key)

        # Use sender's private key to sign plaintext
        if sender.private_key:
            try:
                print("Enc Private:", sender.private_key)
                sender_private_key = decrypt_user_private_key(sender.private_key, sender.key_version)
                print("Dec Private:", sender_private_key)
                signature = sign_data(details, sender_private_key)
            except Exception as e:
                flash(f"Error signing transaction: {e}")
                return redirect(url_for('transaction.new_transaction'))

        # If transaction amount exceed 50000, need the approval of employee
        if amount > 50000:
            if sender.balance < amount:
                flash("Insufficient balance for large transaction. Transaction rejected.")
                return redirect(url_for('transaction.new_transaction'))
            else:
                new_tx = Transaction(
                    sender_id=sender.id,
                    receiver_id=receiver.id,
                    amount=amount,
                    encrypted_details=encrypted_details,
                    integrity_hash=integrity,
                    status="pending",
                    key_version=current_version,
                    signature=signature
                )
                db.session.add(new_tx)
                db.session.commit()
                flash("Transaction is pending employee approval.")
                return redirect(url_for('transaction.view_transactions'))

        else:
            if sender.balance < amount:
                flash("Insufficient balance!")
                return redirect(url_for('transaction.new_transaction'))
            new_tx = Transaction(
                sender_id=sender.id,
                receiver_id=receiver.id,
                amount=amount,
                encrypted_details=encrypted_details,
                integrity_hash=integrity,
                status="approved",
                key_version=current_version,
                signature=signature
            )
            db.session.add(new_tx)
            sender.balance -= amount
            receiver.balance += amount
            db.session.commit()
            flash("Transaction successfully submitted!")
            return redirect(url_for('transaction.view_transactions'))

    return render_template('new_transaction.html')


@transaction_bp.route('/view', methods=['GET'])
def view_transactions():
    if 'user_id' not in session:
        flash("Please log in to view transactions.")
        return redirect(url_for('auth.login'))

    current_user_id = session['user_id']
    transactions = Transaction.query.filter(
        (Transaction.sender_id == current_user_id) |
        (Transaction.receiver_id == current_user_id)
    ).order_by(Transaction.timestamp.desc()).all()

    for tx in transactions:
        decrypted = None
        try:
            key_for_tx = get_key_by_version(tx.key_version)
            encrypted_bytes = bytes.fromhex(tx.encrypted_details)
            # Get the plaintext using AES decrypt
            decrypted = aes_decrypt(encrypted_bytes, key_for_tx)
            tx.decrypted_details = decrypted
            if not verify_hmac(tx.encrypted_details, key_for_tx, tx.integrity_hash):
                tx.decrypted_details += " (Integrity check failed)"
        except Exception as e:
            tx.decrypted_details = f"Decryption error: {e}"

        # Verify digital signature
        if decrypted is not None and tx.signature:
            sender = User.query.get(tx.sender_id)
            if sender and sender.public_key:
                try:
                    if verify_signature(decrypted, tx.signature, sender.public_key.encode("utf-8")):
                        tx.decrypted_details += " (Signature verification succeeded)"
                    else:
                        tx.decrypted_details += " (Signature verification failed)"
                except Exception as e:
                    tx.decrypted_details += f" (Signature verification error: {e})"
            else:
                tx.decrypted_details += " (Sender public key missing)"
        else:
            if decrypted is None:
                tx.decrypted_details += " (Skipping signature verification due to decryption failure)"

        if tx.sender_id == current_user_id:
            receiver = User.query.get(tx.receiver_id)
            tx.counterparty = f"{receiver.username} ({receiver.account_number})" if receiver else "Unknown"
            tx.type_label = "Sent"
        else:
            sender = User.query.get(tx.sender_id)
            tx.counterparty = f"{sender.username} ({sender.account_number})" if sender else "Unknown"
            tx.type_label = "Received"

    return render_template('view_transactions.html', transactions=transactions)
