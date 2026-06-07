import os


class Config:
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_USER = os.getenv("DB_USER", "AdminNetPulse")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "@NetPulse2026")
    DB_NAME = os.getenv("DB_NAME", "netpulse_db")

    SECRET_KEY = os.getenv("SECRET_KEY", "supersecretcode")
