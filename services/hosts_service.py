from flask import current_app

from serializers.hosts_serializer import serialize_hosts


def get_hosts_service():
    db = current_app.mongo.db

    hosts = db.hosts.find({})

    return serialize_hosts(hosts), 200
