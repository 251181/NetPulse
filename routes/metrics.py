from flask import Blueprint, jsonify
from services.metrics_service import get_metrics_service

metrics_bp = Blueprint("metrics", __name__)


@metrics_bp.route("/metrics")
def get_all_metrics():
    metrics, code = get_metrics_service()

    return jsonify(metrics), code

