from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from db.models import User, Transaction
from extensions import db
import random
from db.models import OperationLog

employee_bp = Blueprint('employee', __name__)


# For employees to login in to their account
@employee_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        # Make sure user is employee
        if user and user.check_password(password) and user.role == 'employee':
            # Same as client loging MFA
            otp = str(random.randint(100000, 999999))
            flash(f"Your OTP code is: {otp} (Simulation Only)")
            session['pending_employee'] = {
                'user_id': user.id,
                'username': user.username,
                'role': user.role
            }
            session['employee_mfa_code'] = otp
            return redirect(url_for('employee.mfa'))
        else:
            flash("Invalid credentials or not an employee.")
            return redirect(url_for('employee.login'))
    return render_template('employee_login.html')


# 员工 MFA 验证页面
@employee_bp.route('/mfa', methods=['GET', 'POST'])
def mfa():
    # MFA for employees
    if 'pending_employee' not in session or 'employee_mfa_code' not in session:
        flash("No pending MFA verification. Please log in again.")
        return redirect(url_for('employee.login'))

    if request.method == 'POST':
        input_code = request.form.get('otp')
        if input_code == session.get('employee_mfa_code'):
            pending = session.pop('pending_employee')
            session['user_id'] = pending['user_id']
            session['username'] = pending['username']
            session['role'] = pending['role']
            session.pop('employee_mfa_code', None)
            flash("MFA verification successful. You are now logged in as employee.")
            return redirect(url_for('employee.dashboard'))
        else:
            flash("Incorrect OTP code. Please try again.")
            return redirect(url_for('employee.mfa'))

    return render_template('employee_mfa.html')


# Employee's Dashboard
@employee_bp.route('/dashboard')
def dashboard():
    if 'user_id' not in session or session.get('role') != 'employee':
        flash("Please log in as an employee to access this page.")
        return redirect(url_for('employee.login'))

    # Search all Clients
    customers = User.query.filter_by(role='client').all()
    return render_template('employee_dashboard.html', customers=customers)


# To let employee to view customer's details including name, balance and translations
@employee_bp.route('/customer/<int:user_id>')
def view_customer(user_id):
    if 'user_id' not in session or session.get('role') != 'employee':
        flash("Please log in as an employee to access this page.")
        return redirect(url_for('employee.login'))

    customer = User.query.get(user_id)
    if not customer:
        flash("Customer not found.")
        return redirect(url_for('employee.dashboard'))

    # Search all Clients
    transactions = Transaction.query.filter(
        (Transaction.sender_id == user_id) | (Transaction.receiver_id == user_id)
    ).all()
    return render_template('employee_customer.html', customer=customer, transactions=transactions)


# Only view transactions but do not take actions
@employee_bp.route('/customer/<int:user_id>/review_transactions')
def review_customer_transactions(user_id):
    if 'user_id' not in session or session.get('role') != 'employee':
        flash("Please log in as an employee to access this page.")
        return redirect(url_for('employee.login'))
    customer = User.query.get(user_id)
    if not customer:
        flash("Customer not found.")
        return redirect(url_for('employee.dashboard'))
    transactions = Transaction.query.filter(
        (Transaction.sender_id == user_id) | (Transaction.receiver_id == user_id)
    ).order_by(Transaction.timestamp.desc()).all()
    return render_template('employee_review_customer_transactions.html', customer=customer, transactions=transactions)


# View and take actions
@employee_bp.route('/transaction/<int:tx_id>/review', methods=['GET', 'POST'])
def review_transaction(tx_id):
    if 'user_id' not in session or session.get('role') != 'employee':
        flash("Please log in as an employee to access this page.")
        return redirect(url_for('employee.login'))

    tx = Transaction.query.get(tx_id)
    if not tx:
        flash("Transaction not found.")
        return redirect(url_for('employee.dashboard'))

    sender_user = User.query.get(tx.sender_id)
    receiver_user = User.query.get(tx.receiver_id)

    if request.method == 'POST':
        review_result = request.form.get('review_result')  # "Approved", "Rejected", "Flagged"
        comments = request.form.get('comments')

        from db.models import OperationLog
        log_entry = OperationLog(
            employee_id=session['user_id'],
            operation=f"Reviewed Transaction {tx_id}",
            details=f"Result: {review_result}. Comments: {comments}"
        )
        db.session.add(log_entry)
        db.session.commit()
        flash("Transaction review submitted.")
        return redirect(url_for('employee.dashboard'))

    return render_template(
        'employee_review_transaction.html',
        transaction=tx,
        sender=sender_user,
        receiver=receiver_user
    )


# Update customer's balance
@employee_bp.route('/customer/<int:user_id>/update', methods=['GET', 'POST'])
def update_customer(user_id):
    if 'user_id' not in session or session.get('role') != 'employee':
        flash("Please log in as an employee to access this page.")
        return redirect(url_for('employee.login'))

    customer = User.query.get(user_id)
    if not customer:
        flash("Customer not found.")
        return redirect(url_for('employee.dashboard'))

    if request.method == 'POST':
        # Change balance (assume Client contact to employee to transfer money or some)
        new_balance_str = request.form.get('balance')
        try:
            new_balance = float(new_balance_str)
        except ValueError:
            flash("Invalid balance value.")
            return redirect(url_for('employee.update_customer', user_id=user_id))

        old_balance = customer.balance
        customer.balance = new_balance

        # Record the logs
        from db.models import OperationLog
        log_entry = OperationLog(
            employee_id=session['user_id'],
            operation=f"Updated Customer {customer.username} Balance",
            details=f"Old Balance: {old_balance}, New Balance: {new_balance}"
        )
        db.session.add(log_entry)
        db.session.commit()
        flash("Customer account updated successfully.")
        return redirect(url_for('employee.view_customer', user_id=user_id))

    return render_template('employee_update_customer.html', customer=customer)


@employee_bp.route('/logs')
def view_logs():
    if 'user_id' not in session or session.get('role') != 'employee':
        flash("Please log in as an employee to access this page.")
        return redirect(url_for('employee.login'))

    logs = OperationLog.query.order_by(OperationLog.timestamp.desc()).all()

    return render_template('employee_logs.html', logs=logs)
