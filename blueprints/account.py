from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from db.models import User
from extensions import db

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
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not user.check_password(current_password):
            flash("Current password is incorrect.")
            return redirect(url_for('account.settings'))

        if new_password != confirm_password:
            flash("New passwords do not match.")
            return redirect(url_for('account.settings'))

        user.set_password(new_password)
        db.session.commit()
        flash("Password updated successfully.")
        return redirect(url_for('account.settings'))

    return render_template('settings.html', user=user)