import os
from dotenv import load_dotenv
from datetime import timedelta

load_dotenv(".env.example")


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY")
    PERMANENT_SESSION_LIFETIME = timedelta(
        days=int(os.getenv("SESSION_LIFETIME_DAYS", 30))
    )

    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/NetPulse")

    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
    TELEGRAM_BOT_PASSWORD = os.getenv("TELEGRAM_BOT_PASSWORD")

    AUTH_PASSWORD = os.getenv("AUTH_PASSWORD")
