from flask import Blueprint, jsonify
from services.routers_service import get_routers_service

routers_bp = Blueprint("routers", __name__)


@routers_bp.route("/routers")
def get_routers():
    routers, code = get_routers_service()

    return jsonify(routers), code
