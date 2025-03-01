from apscheduler.schedulers.background import BackgroundScheduler
from crypto.encryption import auto_rotate_master_key


# Use this so this web app can invoke the key rotation function regularly when app is running
def rotate_keys_job(app):
    with app.app_context():
        new_key, new_version = auto_rotate_master_key()
        app.config["ENCRYPTION_KEY"] = new_key
        app.config["KEY_VERSION"] = new_version
        print(f"Rotated key to version: {new_version}")

def init_scheduler(app):
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=lambda: rotate_keys_job(app), trigger="interval", seconds=5)
    scheduler.start()
    app.scheduler = scheduler