import threading
import logging
import click

from flask import Flask
from flask_cors import CORS
from flask_pymongo import PyMongo

from routes.devices import devices_bp
from routes.logs import logs_bp
from routes.metrics import metrics_bp
from routes.events import events_bp
from routes.auth import auth_bp
from routes.frontend import frontend_bp

from core.auth import auth_guard

from config import Config

from workers.main import main
from helpers.notification_manager import start_telegram_system

app = Flask(__name__)

app.config.from_object(Config)

required = [
    "SECRET_KEY",
    "TELEGRAM_BOT_TOKEN",
    "AUTH_PASSWORD",
]

for key in required:
    if not app.config.get(key):
        raise RuntimeError(f"Missing environment variable: {key}")

mongo = PyMongo(app)
app.mongo = mongo

CORS(app, supports_credentials=True)

app.register_blueprint(logs_bp)
app.register_blueprint(devices_bp)
app.register_blueprint(metrics_bp)
app.register_blueprint(events_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(frontend_bp)

@app.before_request
def global_auth_guard():
    return auth_guard()


if __name__ == "__main__":
    logging.getLogger('werkzeug').disabled = True
    logging.getLogger('flask').setLevel(logging.ERROR)
    click.echo = lambda *args, **kwargs: None
    threading.Thread(target=main, daemon=True).start()
    start_telegram_system()
    
    app.run(
        debug=False,
        use_reloader=False,
        host="0.0.0.0",
        port=8000,
        ssl_context=("certs/cert.pem", "certs/key.pem")
    )
