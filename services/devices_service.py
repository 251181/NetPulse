from flask import current_app

from serializers.devices_serializer import serialize_devices


def get_devices_service():
    db = current_app.mongo.db

    devices = list(db.devices.find({
        "general_info.device_type": {
            "$nin": ["Switch"]
        }
    }))

    return serialize_devices(devices), 200
