from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from db.models import User, generate_account_number  # 假设 User 模型中有 username、role、account_number、balance 等字段
from extensions import db
import random
from db.models import OperationLog


admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password) and user.role == 'admin':
            otp = str(random.randint(100000, 999999))
            flash(f"Your OTP code is: {otp} (Simulation Only)")
            session['pending_admin'] = {
                'user_id': user.id,
                'username': user.username,
                'role': user.role
            }
            session['admin_mfa_code'] = otp
            return redirect(url_for('admin.mfa'))
        else:
            flash("Invalid credentials or not an admin.")
            return redirect(url_for('admin.login'))
    return render_template('admin_login.html')

# MFA For Admin
@admin_bp.route('/mfa', methods=['GET', 'POST'])
def mfa():
    if 'pending_admin' not in session or 'admin_mfa_code' not in session:
        flash("No pending MFA verification. Please log in again.")
        return redirect(url_for('admin.login'))
    if request.method == 'POST':
        input_code = request.form.get('otp')
        if input_code == session.get('admin_mfa_code'):
            pending = session.pop('pending_admin')
            session['user_id'] = pending['user_id']
            session['username'] = pending['username']
            session['role'] = pending['role']
            session.pop('admin_mfa_code', None)
            flash("MFA verification successful. You are now logged in as admin.")
            return redirect(url_for('admin.dashboard'))
        else:
            flash("Incorrect OTP code. Please try again.")
            return redirect(url_for('admin.mfa'))
    return render_template('admin_mfa.html')


@admin_bp.route('/dashboard')
def dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Please log in as an admin to access this page.")
        return redirect(url_for('admin.login'))
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)



@admin_bp.route('/user/<int:user_id>/update_role', methods=['GET', 'POST'])
def update_role(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Please log in as an admin to access this page.")
        return redirect(url_for('admin.login'))
    user = User.query.get(user_id)
    if not user:
        flash("User not found.")
        return redirect(url_for('admin.dashboard'))
    if request.method == 'POST':
        new_role = request.form.get('role')
        if new_role not in ['client', 'employee', 'admin']:
            flash("Invalid role.")
            return redirect(url_for('admin.update_role', user_id=user_id))
        old_role = user.role
        user.role = new_role
        db.session.commit()
        flash(f"User role updated from {old_role} to {new_role}.")
        return redirect(url_for('admin.dashboard'))
    return render_template('admin_update_role.html', user=user)


@admin_bp.route('/logout')
def logout():
    session.clear()
    flash("Admin has been logged out.")
    return redirect(url_for('index'))


@admin_bp.route('/add_employee', methods=['GET', 'POST'])
def add_employee():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Please log in as an admin to access this page.")
        return redirect(url_for('admin.login'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash("Username and password are required!")
            return redirect(url_for('admin.add_employee'))

        if User.query.filter_by(username=username).first():
            flash("Username already exists!")
            return redirect(url_for('admin.add_employee'))

        new_emp = User(
            username=username,
            account_number=generate_account_number(),
            balance=0.0,
            role="employee"
        )
        new_emp.set_password(password)
        db.session.add(new_emp)
        db.session.commit()
        flash("New employee account created!")
        return redirect(url_for('admin.dashboard'))

    return render_template('admin_add_employee.html')


@admin_bp.route('/employee/<int:employee_id>/update', methods=['GET', 'POST'])
def update_employee(employee_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Please log in as an admin to access this page.")
        return redirect(url_for('admin.login'))

    employee = User.query.filter_by(id=employee_id, role='employee').first()
    if not employee:
        flash("Employee not found.")
        return redirect(url_for('admin.dashboard'))

    if request.method == 'POST':
        new_username = request.form.get('username')
        new_password = request.form.get('password')
        if new_username:
            employee.username = new_username
        if new_password:
            employee.set_password(new_password)
        db.session.commit()
        flash("Employee account updated successfully.")
        return redirect(url_for('admin.dashboard'))

    return render_template('admin_update_employee.html', employee=employee)


@admin_bp.route('/audit')
def audit():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Please log in as an admin to access this page.")
        return redirect(url_for('admin.login'))

    logs = OperationLog.query.order_by(OperationLog.timestamp.desc()).all()

    for log in logs:
        employee = User.query.get(log.employee_id)
        log.employee_name = employee.username if employee else "Unknown Employee"

    return render_template('admin_audit.html', logs=logs)
