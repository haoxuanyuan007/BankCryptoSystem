from flask import Flask, render_template, session
from config import Config
from extensions import db
from flask_migrate import Migrate
from blueprints.auth import auth_bp
from db.models import User
from blueprints.transaction import transaction_bp
from blueprints.account import account_bp
from blueprints.employee import employee_bp
from blueprints.message import message_bp
from blueprints.admin import admin_bp
from utils.utils import mask_account_number

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
migrate = Migrate(app, db)

app.register_blueprint(auth_bp, url_prefix='/auth')

app.register_blueprint(transaction_bp, url_prefix='/transaction')

app.register_blueprint(account_bp, url_prefix='/account')

app.register_blueprint(employee_bp, url_prefix='/employee')

app.register_blueprint(message_bp, url_prefix='/message')

app.register_blueprint(admin_bp, url_prefix='/admin')

@app.route('/')
def index():
    user_info = None
    if 'user_id' in session:
        user_info = User.query.get(session['user_id'])
        if user_info:
            user_info.account_number = mask_account_number(user_info.account_number)
    return render_template('index.html', user_info=user_info)

if __name__ == '__main__':
    app.run(ssl_context=('cert.pem', 'key.pem'), debug=True)
