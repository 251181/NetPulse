import threading

from flask import Flask
from flask_cors import CORS
from flask_pymongo import PyMongo

from workers.backend import backend
from routes.routers import routers_bp
from routes.events import events_bp
from routes.auth import auth_bp

app = Flask(__name__)

app.config["MONGO_URI"] = "mongodb://localhost:27017/NetPulse"

mongo = PyMongo(app)
app.mongo = mongo

CORS(app)

app.register_blueprint(routers_bp)
app.register_blueprint(events_bp)
app.register_blueprint(auth_bp)

if __name__ == "__main__":
    threading.Thread(target=backend, daemon=True).start()
    app.run(debug=True, host="0.0.0.0", port=8000)
