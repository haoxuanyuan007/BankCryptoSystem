from flask import Blueprint, request, render_template, redirect, url_for, flash, session
from extensions import db
from db.models import Transaction
from datetime import datetime
from crypto.encryption import aes_encrypt, aes_decrypt
from config import Config
from crypto.integrity import generate_hmac, verify_hmac
from db.models import User

transaction_bp = Blueprint('transaction', __name__)


@transaction_bp.route('/new', methods=['GET', 'POST'])
def new_transaction():
    if 'user_id' not in session:
        flash("Please log in to initiate a transaction.")
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        # User can use name or account number
        receiver_input = request.form.get('receiver')
        amount_str = request.form.get('amount')
        details = request.form.get('details')

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

        # Get sender info
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

        # Check the balance
        if sender.balance < amount:
            flash("Insufficient balance!")
            return redirect(url_for('transaction.new_transaction'))

        # Encrypt the details
        encryption_key = Config.ENCRYPTION_KEY
        encrypted_bytes = aes_encrypt(details, encryption_key)
        encrypted_details = encrypted_bytes.hex()
        integrity = generate_hmac(encrypted_details, encryption_key)

        # Update balance for both sender and receiver
        sender.balance -= amount
        receiver.balance += amount

        # Create the transaction record
        new_tx = Transaction(
            sender_id=sender.id,
            receiver_id=receiver.id,
            amount=amount,
            encrypted_details=encrypted_details,
            integrity_hash=integrity
        )
        db.session.add(new_tx)
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
    # Search all transactions for current user
    transactions = Transaction.query.filter(
        (Transaction.sender_id == current_user_id) |
        (Transaction.receiver_id == current_user_id)
    ).all()

    encryption_key = Config.ENCRYPTION_KEY
    for tx in transactions:
        try:
            # Decrypt the transaction
            encrypted_bytes = bytes.fromhex(tx.encrypted_details)
            decrypted = aes_decrypt(encrypted_bytes, encryption_key)
            tx.decrypted_details = decrypted
            # Verify the integrity
            if not verify_hmac(tx.encrypted_details, encryption_key, tx.integrity_hash):
                tx.decrypted_details += " (Integrity check failed)"
        except Exception as e:
            tx.decrypted_details = f"Decryption error: {e}"

        # Show the details on template (The role of sender and receiver)
        if tx.sender_id == current_user_id:
            receiver = User.query.get(tx.receiver_id)
            if receiver:
                tx.counterparty = f"{receiver.username} ({receiver.account_number})"
            else:
                tx.counterparty = "Unknown"
        else:
            sender = User.query.get(tx.sender_id)
            if sender:
                tx.counterparty = f"{sender.username} ({sender.account_number})"
            else:
                tx.counterparty = "Unknown"

    return render_template('view_transactions.html', transactions=transactions)