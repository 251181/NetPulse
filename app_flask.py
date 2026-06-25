import threading
import logging
import click

from datetime import timedelta


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

from workers.main import main
from helpers.notification_manager import start_telegram_system

app = Flask(__name__)

app.config["MONGO_URI"] = "mongodb://localhost:27017/NetPulse"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

mongo = PyMongo(app)
app.mongo = mongo

CORS(app, supports_credentials=True)

app.register_blueprint(logs_bp)
app.register_blueprint(devices_bp)
app.register_blueprint(metrics_bp)
app.register_blueprint(events_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(frontend_bp)

app.secret_key = "#@W$*YU%&*(WYEGHWH*(HG(*SCHBGVHUSICHVBUIh)))"
app.permanent_session_lifetime = timedelta(days=30)

@app.before_request
def global_auth_guard():
    return auth_guard()

if __name__ == "__main__":
    app.run(
        debug=False,
        use_reloader=False,
        host="0.0.0.0",
        port=8000,
        ssl_context=("certs/cert.pem", "certs/key.pem")
    )
