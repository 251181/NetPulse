import threading
import logging

from flask import Flask
from flask_cors import CORS
from flask_pymongo import PyMongo

from routes.devices import devices_bp
from routes.logs import logs_bp
from routes.metrics import metrics_bp
from routes.events import events_bp
from routes.auth import auth_bp
from routes.frontend import frontend_bp

from workers.main import main

app = Flask(__name__)

app.config["MONGO_URI"] = "mongodb://localhost:27017/NetPulse"

mongo = PyMongo(app)
app.mongo = mongo

CORS(app)

app.register_blueprint(logs_bp)
app.register_blueprint(devices_bp)
app.register_blueprint(metrics_bp)
app.register_blueprint(events_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(frontend_bp)

if __name__ == "__main__":
    app.run(debug=False, use_reloader=False, host="0.0.0.0", port=8000)
    
