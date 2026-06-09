from flask import current_app

from serializers.routers_serializer import serialize_routers


def get_routers_service():
    db = current_app.mongo.db

    routers = list(db.devices.find({"general_info.device_type": "Router"}))

    return serialize_routers(routers), 200
