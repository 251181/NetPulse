import time
import threading

ALERT_COOLDOWN = 1800

last_alerts = {}
last_alerts_lock = threading.Lock()


def should_send_alert(event):
    key = (event["type"], event["ip"])
    now = time.time()

    with last_alerts_lock:
        last_time = last_alerts.get(key)

        if last_time and now - last_time < ALERT_COOLDOWN:
            return False

        last_alerts[key] = now
        return True
