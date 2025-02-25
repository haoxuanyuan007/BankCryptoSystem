from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from db.models import Message, User
from extensions import db
from config import Config
from crypto.encryption import aes_encrypt, aes_decrypt
from crypto.integrity import generate_hmac, verify_hmac

message_bp = Blueprint('message', __name__)


@message_bp.route('/send', methods=['GET', 'POST'])
def send_message():
    # Have to log in
    if 'user_id' not in session:
        flash("Please log in to send messages.")
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        receiver_input = request.form.get('receiver')  # 收件方用户名或账户号
        content = request.form.get('content')

        if not receiver_input or not content:
            flash("All fields are required!")
            return redirect(url_for('message.send_message'))

        # Try account number first, then the name
        receiver = User.query.filter_by(account_number=receiver_input).first()
        if not receiver:
            receiver = User.query.filter_by(username=receiver_input).first()
        if not receiver:
            flash("Receiver not found.")
            return redirect(url_for('message.send_message'))

        encryption_key = Config.ENCRYPTION_KEY
        # Encry pt the message using AES that implemented before, convert to hex string to store
        encrypted_bytes = aes_encrypt(content, encryption_key)
        encrypted_content = encrypted_bytes.hex()
        # Generate hmac.
        integrity = generate_hmac(encrypted_content, encryption_key)

        new_msg = Message(
            sender_id=session['user_id'],
            receiver_id=receiver.id,
            encrypted_content=encrypted_content,
            integrity_hash=integrity
        )
        db.session.add(new_msg)
        db.session.commit()
        flash("Message sent successfully!")
        return redirect(url_for('message.outbox'))

    return render_template('send_message.html')


@message_bp.route('/inbox', methods=['GET'])
def inbox():
    if 'user_id' not in session:
        flash("Please log in to view your inbox.")
        return redirect(url_for('auth.login'))

    current_user_id = session['user_id']
    # Search the messages for current user as a receiver role
    messages = Message.query.filter_by(receiver_id=current_user_id).order_by(Message.timestamp.desc()).all()
    encryption_key = Config.ENCRYPTION_KEY
    for msg in messages:
        try:
            # Convert hex string back to bytes and decrypt
            encrypted_bytes = bytes.fromhex(msg.encrypted_content)
            decrypted = aes_decrypt(encrypted_bytes, encryption_key)
            msg.decrypted_content = decrypted
            if not verify_hmac(msg.encrypted_content, encryption_key, msg.integrity_hash):
                msg.decrypted_content += " (Integrity check failed)"
        except Exception as e:
            msg.decrypted_content = f"Decryption error: {e}"

        # Get sender info
        sender = User.query.get(msg.sender_id)
        msg.sender_info = sender.username if sender else "Unknown"

    return render_template('inbox.html', messages=messages)


@message_bp.route('/outbox', methods=['GET'])
def outbox():
    if 'user_id' not in session:
        flash("Please log in to view your outbox.")
        return redirect(url_for('auth.login'))

    current_user_id = session['user_id']
    # Search the messages for current user as a sender role
    messages = Message.query.filter_by(sender_id=current_user_id).order_by(Message.timestamp.desc()).all()
    encryption_key = Config.ENCRYPTION_KEY
    for msg in messages:
        try:
            encrypted_bytes = bytes.fromhex(msg.encrypted_content)
            decrypted = aes_decrypt(encrypted_bytes, encryption_key)
            msg.decrypted_content = decrypted
            if not verify_hmac(msg.encrypted_content, encryption_key, msg.integrity_hash):
                msg.decrypted_content += " (Integrity check failed)"
        except Exception as e:
            msg.decrypted_content = f"Decryption error: {e}"

        # Get receiver info
        receiver = User.query.get(msg.receiver_id)
        msg.receiver_info = receiver.username if receiver else "Unknown"

    return render_template('outbox.html', messages=messages)