from flask import Blueprint, send_from_directory

frontend_bp = Blueprint("frontend", __name__)


@frontend_bp.route("/")
def frontend():
    return send_from_directory("static", "index5.html")
