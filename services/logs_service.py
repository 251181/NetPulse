from flask import current_app

from serializers.logs_serializer import serialize_logs


def get_logs_service():
    db = current_app.mongo.db

    logs = list(db.logs.find({}))

    return serialize_logs(logs), 200
