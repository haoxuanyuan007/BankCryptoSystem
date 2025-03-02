from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from db.models import User
from extensions import db
from crypto.encryption import aes_encrypt, aes_decrypt, get_key_by_version
from config import Config
from crypto.integrity import generate_hmac, verify_hmac

account_bp = Blueprint('account', __name__)


# For Clients to deposit money (Simulation)
@account_bp.route('/deposit', methods=['GET', 'POST'])
def deposit():
    if 'user_id' not in session:
        flash("Please log in to deposit funds.")
        return redirect(url_for('auth.login'))

    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        amount_str = request.form.get('amount')
        try:
            amount = float(amount_str)
        except ValueError:
            flash("Invalid deposit amount.")
            return redirect(url_for('account.deposit'))

        if amount <= 0:
            flash("Deposit amount must be greater than 0.")
            return redirect(url_for('account.deposit'))

        user.balance += amount
        db.session.commit()
        flash(f"Successfully deposited ${amount:.2f}. New balance: ${user.balance:.2f}.")
        return redirect(url_for('index'))

    return render_template('deposit.html', user=user)


# For Client to withdraw money (Simulation)
@account_bp.route('/withdraw', methods=['GET', 'POST'])
def withdraw():
    if 'user_id' not in session:
        flash("Please log in to withdraw funds.")
        return redirect(url_for('auth.login'))

    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        amount_str = request.form.get('amount')
        try:
            amount = float(amount_str)
        except ValueError:
            flash("Invalid withdrawal amount.")
            return redirect(url_for('account.withdraw'))

        if amount <= 0:
            flash("Withdrawal amount must be greater than 0.")
            return redirect(url_for('account.withdraw'))

        if user.balance < amount:
            flash("Insufficient balance.")
            return redirect(url_for('account.withdraw'))

        user.balance -= amount
        db.session.commit()
        flash(f"Successfully withdrew ${amount:.2f}. New balance: ${user.balance:.2f}.")
        return redirect(url_for('index'))

    return render_template('withdraw.html', user=user)


# Allow Clients to changer their password
@account_bp.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user_id' not in session:
        flash("Please log in to access account settings.")
        return redirect(url_for('auth.login'))

    user = User.query.get(session['user_id'])
    # Can't use Config.ENCRYPTION_KEY here, because key might not be updated and address maybe old

    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        new_username = request.form.get('new_username')
        new_address = request.form.get('new_address')
        new_contact = request.form.get('new_contact')

        # Verify Current Password
        if not user.check_password(current_password):
            flash("Current password is incorrect.")
            return redirect(url_for('account.settings'))

        # Update Password
        if new_password:
            if new_password != confirm_password:
                flash("New passwords do not match.")
                return redirect(url_for('account.settings'))
            user.set_password(new_password)
            flash("Password updated successfully.")

        # Update Username
        if new_username:
            user.username = new_username
            flash("Username updated successfully.")

        # Update Address
        if new_address:
            # Get Correct Key Version
            current_key = Config.ENCRYPTION_KEY
            current_version = Config.KEY_VERSION
            enc_bytes = aes_encrypt(new_address, current_key)
            user.address = enc_bytes.hex()
            user.key_version = current_version
            user.address_integrity_hash = generate_hmac(user.address, current_key)
            flash("Address updated successfully.")

        if new_contact:
            current_key = Config.ENCRYPTION_KEY
            current_version = Config.KEY_VERSION
            enc_bytes = aes_encrypt(new_contact, current_key)
            user.contact = enc_bytes.hex()
            user.key_version = current_version
            user.contact_integrity_hash = generate_hmac(user.contact, current_key)
            flash("Contact updated successfully.")

        db.session.commit()
        return redirect(url_for('account.settings'))

    # To show user the address
    if user.address:
        try:
            # Find Correct Key Version
            key_for_addr = get_key_by_version(user.key_version)
            encrypted_bytes = bytes.fromhex(user.address)
            decrypted = aes_decrypt(encrypted_bytes, key_for_addr)
            decrypted_address = decrypted
            if not verify_hmac(user.address, key_for_addr, user.address_integrity_hash):
                decrypted_address += " (Integrity check failed)"
        except Exception as e:
            decrypted_address = f"Error decrypting address: {e}"
    else:
        decrypted_address = "Address not set"

    # To show user the contact
    if user.contact:
        try:
            key_for_contact = get_key_by_version(user.key_version)
            encrypted_bytes = bytes.fromhex(user.contact)
            decrypted = aes_decrypt(encrypted_bytes, key_for_contact)
            decrypted_contact = decrypted
            if not verify_hmac(user.contact, key_for_contact, user.contact_integrity_hash):
                decrypted_contact += " (Integrity check failed)"
        except Exception as e:
            decrypted_contact = f"Error decrypting contact: {e} (Format is not right or Contact is Empty)"
    else:
        decrypted_contact = "Contact not set"

    return render_template('settings.html', user=user, decrypted_address=decrypted_address,
                           decrypted_contact=decrypted_contact)
