import queue
import threading
from helpers.alert_cooldown_manager import should_send_alert

clients = []
clients_lock = threading.Lock()
notification_queue = queue.Queue()


def register_client():
    q = queue.Queue()

    with clients_lock:
        clients.append(q)

    return q


def unregister_client(q):
    with clients_lock:
        if q in clients:
            clients.remove(q)


def push_event(event):
    if not should_send_alert(event):
        return

    with clients_lock:
        for q in clients:
            q.put(event)

    notification_queue.put(event)
