from flask import current_app

from serializers.metrics_serializer import serialize_metrics
from collections import defaultdict


def get_metrics_service():
    db = current_app.mongo.db

    allowed_ips = db.devices.find(
        {"general_info.device_type": {"$ne": "Switch"}},
        {"ip": 1, "_id": 0}
    )

    allowed_ip_set = {d["ip"] for d in allowed_ips if "ip" in d}

    cursor = db.metrics.find(
        {"ip": {"$in": list(allowed_ip_set)}}
    ).sort("timestamp", 1)

    grouped = defaultdict(list)

    for m in cursor:
        grouped[m["ip"]].append(m)

    return serialize_metrics(grouped), 200
