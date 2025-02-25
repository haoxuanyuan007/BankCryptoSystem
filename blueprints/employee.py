from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from db.models import User, Transaction
from extensions import db
import random
from db.models import OperationLog
from config import Config
from crypto.encryption import aes_decrypt, aes_encrypt
from crypto.integrity import generate_hmac, verify_hmac

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


# MFA For Employees
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

    # Get employee's name
    for log in logs:
        employee = User.query.get(log.employee_id)
        print(employee)
        log.employee_name = employee.username if employee else "Unknown Employee"



    return render_template('employee_logs.html', logs=logs)


@employee_bp.route('/pending_transactions')
def pending_transactions():
    if 'user_id' not in session or session.get('role') != 'employee':
        flash("Please log in as an employee to access this page.")
        return redirect(url_for('employee.login'))

    pending_tx = Transaction.query.filter_by(status='pending').order_by(Transaction.timestamp.desc()).all()

    # Decrypt Details
    encryption_key = Config.ENCRYPTION_KEY
    for tx in pending_tx:
        try:
            enc_bytes = bytes.fromhex(tx.encrypted_details)
            decrypted = aes_decrypt(enc_bytes, encryption_key)
            tx.decrypted_details = decrypted
        except Exception as e:
            tx.decrypted_details = f"Decrypt error: {e}"

    parties = {}
    for tx in pending_tx:
        sender = User.query.get(tx.sender_id)
        receiver = User.query.get(tx.receiver_id)
        parties[tx.id] = {
            'sender': sender,
            'receiver': receiver
        }


    return render_template(
        'employee_pending_transactions.html',
        transactions=pending_tx,
        parties=parties
    )


@employee_bp.route('/transaction/<int:tx_id>/approve', methods=['POST'])
def approve_transaction(tx_id):
    if 'user_id' not in session or session.get('role') != 'employee':
        flash("Please log in as an employee to access this page.")
        return redirect(url_for('employee.login'))

    tx = Transaction.query.get(tx_id)
    if not tx or tx.status != 'pending':
        flash("Transaction not found or not pending.")
        return redirect(url_for('employee.pending_transactions'))

    sender = User.query.get(tx.sender_id)
    receiver = User.query.get(tx.receiver_id)
    if sender.balance < tx.amount:
        flash("Insufficient balance in sender's account.")
        return redirect(url_for('employee.pending_transactions'))

    sender.balance -= tx.amount
    receiver.balance += tx.amount
    tx.status = 'approved'

    from db.models import OperationLog
    log_entry = OperationLog(
        employee_id=session['user_id'],
        operation=f"Approved Transaction {tx_id}",
        details="Approved pending transaction."
    )
    db.session.add(log_entry)
    db.session.commit()
    flash("Transaction approved successfully.")
    return redirect(url_for('employee.pending_transactions'))


@employee_bp.route('/transaction/<int:tx_id>/reject', methods=['POST'])
def reject_transaction(tx_id):
    if 'user_id' not in session or session.get('role') != 'employee':
        flash("Please log in as an employee to access this page.")
        return redirect(url_for('employee.login'))

    tx = Transaction.query.get(tx_id)
    if not tx or tx.status != 'pending':
        flash("Transaction not found or not pending.")
        return redirect(url_for('employee.pending_transactions'))

    tx.status = 'rejected'

    from db.models import OperationLog
    log_entry = OperationLog(
        employee_id=session['user_id'],
        operation=f"Rejected Transaction {tx_id}",
        details="Rejected pending transaction."
    )
    db.session.add(log_entry)
    db.session.commit()
    flash("Transaction rejected successfully.")
    return redirect(url_for('employee.pending_transactions'))


@employee_bp.route('/customer/<int:user_id>/update_info', methods=['GET', 'POST'])
def update_client_info(user_id):
    if 'user_id' not in session or session.get('role') not in ['employee', 'admin']:
        flash("Please log in as an employee to access this page.")
        return redirect(url_for('employee.login'))

    # Get Client ID
    client = User.query.filter_by(id=user_id, role='client').first()
    if not client:
        flash("Client not found.")
        return redirect(url_for('employee.dashboard'))

    encryption_key = Config.ENCRYPTION_KEY


    # Decrypt Address
    decrypted_address = ""
    if client.address:
        try:
            decrypted_address = aes_decrypt(bytes.fromhex(client.address), encryption_key)
        except Exception as e:
            decrypted_address = "Decryption error"


    if request.method == 'POST':
        new_username = request.form.get('new_username')
        new_address = request.form.get('new_address')
        new_password = request.form.get('new_password')

        # If username was entered, update
        if new_username:
            client.username = new_username

        # If address was entered, update
        if new_address:
            encrypted_address = aes_encrypt(new_address, encryption_key).hex()
            client.address = encrypted_address

        if new_password:
            client.set_password(new_password)

        db.session.commit()
        flash("Client info updated successfully.")
        return redirect(url_for('employee.dashboard', user_id=user_id))

    return render_template('employee_update_client_info.html',
                           client=client, decrypted_address=decrypted_address)


# Make Transaction on Behalf of Client
@employee_bp.route('/make_transaction', methods=['GET', 'POST'])
# Transaction between clients
def make_transaction():
    if 'user_id' not in session or session.get('role') not in ['employee', 'admin']:
        flash("Please log in as an employee to access this page.")
        return redirect(url_for('employee.login'))

    if request.method == 'POST':
        sender_id = request.form.get('sender_id')
        receiver_id = request.form.get('receiver_id')
        amount_str = request.form.get('amount')
        details = request.form.get('details')

        if not sender_id or not receiver_id or not amount_str or not details:
            flash("All fields are required!")
            return redirect(url_for('employee.make_transaction'))

        try:
            amount = float(amount_str)
        except ValueError:
            flash("Invalid amount!")
            return redirect(url_for('employee.make_transaction'))

        if amount <= 0:
            flash("Amount must be greater than 0!")
            return redirect(url_for('employee.make_transaction'))

        sender = User.query.get(sender_id)
        receiver = User.query.get(receiver_id)
        if not sender or not receiver:
            flash("Sender or receiver not found.")
            return redirect(url_for('employee.make_transaction'))

        if sender.balance < amount:
            flash("Insufficient balance in sender account!")
            return redirect(url_for('employee.make_transaction'))

        # Encrypt and generate hmac
        encryption_key = Config.ENCRYPTION_KEY
        encrypted_bytes = aes_encrypt(details, encryption_key)
        encrypted_details = encrypted_bytes.hex()
        integrity = generate_hmac(encrypted_details, encryption_key)

        # Auto approve since this is made by employee, assume client already had communicate with employee
        new_tx = Transaction(
            sender_id=sender.id,
            receiver_id=receiver.id,
            amount=amount,
            encrypted_details=encrypted_details,
            integrity_hash=integrity,
            status="approved"
        )
        sender.balance -= amount
        receiver.balance += amount
        db.session.add(new_tx)
        db.session.commit()

        flash("Transaction processed successfully!")
        return redirect(url_for('employee.dashboard'))

        # GET: Get all Clients
    clients = User.query.filter_by(role='client').all()
    return render_template('employee_make_transaction.html', clients=clients)