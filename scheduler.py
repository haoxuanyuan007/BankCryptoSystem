from apscheduler.schedulers.background import BackgroundScheduler
from crypto.encryption import auto_rotate_master_key, get_rotation_time
from config import Config

def rotate_keys_job(app):
    with app.app_context():
        new_key, new_version = auto_rotate_master_key()
        app.config["ENCRYPTION_KEY"] = new_key
        app.config["KEY_VERSION"] = new_version
        Config.ENCRYPTION_KEY = new_key
        Config.KEY_VERSION = new_version
        print(f"Rotated key to version: {new_version}")

def init_scheduler(app):
    scheduler = BackgroundScheduler()
    with app.app_context():
        interval_seconds = get_rotation_time()
    scheduler.add_job(
        func=lambda: rotate_keys_job(app),
        trigger="interval",
        seconds=interval_seconds,
        id="rotate_keys_job",
        replace_existing=True
    )
    scheduler.start()
    app.scheduler = scheduler