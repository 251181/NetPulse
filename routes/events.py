from flask import Blueprint, Response
import json
from core.event_bus import event_queue

events_bp = Blueprint("events", __name__)


def event_generator():
    while True:
        event = event_queue.get()
        yield f"data: {json.dumps(event)}\n\n"


@events_bp.route("/events")
def generate_event():
    return Response(event_generator(), mimetype="text/event-stream")
