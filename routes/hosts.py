from flask import Blueprint, jsonify
from services.hosts_service import get_hosts_service

hosts_bp = Blueprint("hosts", __name__)


@hosts_bp.route("/hosts/<router_ip>")
def get_hosts_by_router_ip():
    hosts, code = get_hosts_service()

    return jsonify(hosts), code
