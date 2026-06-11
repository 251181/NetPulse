from flask import Blueprint, jsonify
from services.devices_service import get_devices_service

devices_bp = Blueprint("devices", __name__)


@devices_bp.route("/devices")
def get_devices():
    devices, code = get_devices_service()

    return jsonify(devices), code
