from flask import Blueprint, jsonify
from services.logs_service import get_logs_service

logs_bp = Blueprint("logs", __name__)


@logs_bp.route("/logs")
def get_logs():
    logs, code = get_logs_service()

    return jsonify(logs), code