from flask import Blueprint, request, render_template, redirect, url_for, flash, session
from db.models import User, generate_account_number
from extensions import db
import random

auth_bp = Blueprint('auth', __name__)

# For Clients to Register the Account
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash("Username and password are required!")
            return redirect(url_for('auth.register'))

        if User.query.filter_by(username=username).first():
            flash("Username already exists!")
            return redirect(url_for('auth.register'))

        new_user = User(
            username=username,
            account_number=generate_account_number(),
            balance=0.0  # Initial Balance 0
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please log in.")
        return redirect(url_for('auth.login'))

    return render_template('register.html')

# For Clients, Employees and Administrators to Login
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            # Generate 6 digit OTP code
            otp_code = str(random.randint(100000, 999999))
            # In real word application this should send code to client's email or phone, here just provide code on
            # website for simulation.
            flash(f"Your OTP code is: {otp_code} (Simulation Only)")

            # Store user info for verification
            session['pending_user'] = {
                'user_id': user.id,
                'username': user.username,
                'role': user.role
            }
            session['mfa_code'] = otp_code
            # MFA page
            return redirect(url_for('auth.mfa'))
        else:
            flash("Invalid username or password!")
            return redirect(url_for('auth.login'))

    return render_template('login.html')


@auth_bp.route('/mfa', methods=['GET', 'POST'])
def mfa():
    # See if there is user information for verification and OTP code
    if 'pending_user' not in session or 'mfa_code' not in session:
        flash("No pending MFA verification. Please log in again.")
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        input_code = request.form.get('otp')
        if input_code == session.get('mfa_code'):
            # MFA Success, put information into session
            pending_user = session.pop('pending_user')
            session['user_id'] = pending_user['user_id']
            session['username'] = pending_user['username']
            session['role'] = pending_user['role']
            session.pop('mfa_code', None)
            flash("MFA verification successful. You are now logged in.")
            return redirect(url_for('index'))
        else:
            flash("Incorrect OTP code. Please try again.")
            return redirect(url_for('auth.mfa'))

    return render_template('mfa.html')



# Logout Feature
@auth_bp.route('/logout')
def logout():
    session.clear()  # Remove session histories
    flash("You have been logged out.")
    return redirect(url_for('index'))

