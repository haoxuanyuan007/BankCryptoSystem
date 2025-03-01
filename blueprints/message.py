from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from db.models import Message, User
from extensions import db
from config import Config
from crypto.encryption import aes_encrypt, aes_decrypt, get_key_by_version
from crypto.integrity import generate_hmac, verify_hmac

message_bp = Blueprint('message', __name__)


@message_bp.route('/send', methods=['GET', 'POST'])
def send_message():
    # Need login to send message
    if 'user_id' not in session:
        flash("Please log in to send messages.")
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        receiver_input = request.form.get('receiver')  # Receiver data
        content = request.form.get('content')

        if not receiver_input or not content:
            flash("All fields are required!")
            return redirect(url_for('message.send_message'))

        # Try to use account number find receiver first, then user name
        receiver = User.query.filter_by(account_number=receiver_input).first()
        if not receiver:
            receiver = User.query.filter_by(username=receiver_input).first()
        if not receiver:
            flash("Receiver not found.")
            return redirect(url_for('message.send_message'))

        # Get correct key version
        current_version = Config.KEY_VERSION
        encryption_key = Config.ENCRYPTION_KEY

        # Encrypt the message
        encrypted_bytes = aes_encrypt(content, encryption_key)
        encrypted_content = encrypted_bytes.hex()

        # Generate HMAC
        integrity = generate_hmac(encrypted_content, encryption_key)

        # Put the new message into database
        new_msg = Message(
            sender_id=session['user_id'],
            receiver_id=receiver.id,
            encrypted_content=encrypted_content,
            integrity_hash=integrity,
            key_version=current_version
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

    # Current user as a receiver
    messages = Message.query.filter_by(receiver_id=current_user_id).order_by(Message.timestamp.desc()).all()

    for msg in messages:
        try:
            # Get correct key version
            key_for_msg = get_key_by_version(msg.key_version)
            encrypted_bytes = bytes.fromhex(msg.encrypted_content)
            decrypted = aes_decrypt(encrypted_bytes, key_for_msg)
            msg.decrypted_content = decrypted

            # Verify HMAC
            if not verify_hmac(msg.encrypted_content, key_for_msg, msg.integrity_hash):
                msg.decrypted_content += " (Integrity check failed)"
        except Exception as e:
            msg.decrypted_content = f"Decryption error: {e}"

        # Get sender's HMAC
        sender = User.query.get(msg.sender_id)
        msg.sender_info = sender.username if sender else "Unknown"

    return render_template('inbox.html', messages=messages)


@message_bp.route('/outbox', methods=['GET'])
def outbox():
    if 'user_id' not in session:
        flash("Please log in to view your outbox.")
        return redirect(url_for('auth.login'))

    current_user_id = session['user_id']
    # Current user as sender
    messages = Message.query.filter_by(sender_id=current_user_id).order_by(Message.timestamp.desc()).all()

    for msg in messages:
        try:
            # Get correct version
            key_for_msg = get_key_by_version(msg.key_version)
            encrypted_bytes = bytes.fromhex(msg.encrypted_content)
            decrypted = aes_decrypt(encrypted_bytes, key_for_msg)
            msg.decrypted_content = decrypted

            # Verify HMAC
            if not verify_hmac(msg.encrypted_content, key_for_msg, msg.integrity_hash):
                msg.decrypted_content += " (Integrity check failed)"
        except Exception as e:
            msg.decrypted_content = f"Decryption error: {e}"

        receiver = User.query.get(msg.receiver_id)
        msg.receiver_info = receiver.username if receiver else "Unknown"

    return render_template('outbox.html', messages=messages)