from flask import Blueprint, Response
import json
from queue import Empty
from core.event_bus import register_client, unregister_client

events_bp = Blueprint("events", __name__)


def event_generator():
    q = register_client()

    try:
        while True:
            try:
                event = q.get(timeout=15)
                yield f"data: {json.dumps(event, default=str)}\n\n"

            except Empty:
                yield ":\n\n"

    except (GeneratorExit, BrokenPipeError, ConnectionResetError):
        return

    finally:
        unregister_client(q)

@events_bp.route("/events")
def generate_event():
    return Response(event_generator(), mimetype="text/event-stream")
