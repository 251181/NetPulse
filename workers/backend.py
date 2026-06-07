import time
from core.event_bus import event_queue


def backend():
    while True:
        time.sleep(2)

        event_queue.put({
            "type": "info",
            "message": "Backend heartbeat"
        })
