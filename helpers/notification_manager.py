import requests
import time
import threading
from core.event_bus import notification_queue
from db_tools.db_tools import store_subscriber, get_subscribers, remove_subscriber

from zoneinfo import ZoneInfo
WARSAW_TZ = ZoneInfo("Europe/Warsaw")


TOKEN = "8951336705:AAG4K_cwT2FLH3po48JaJ1cMNK7oRF0ZI3k"
SECRET_PASSWORD = "@NetPulseAdmin"

last_update_id = 0


def telegram_polling_loop():
    global last_update_id

    while True:
        try:
            url = (
                f"https://api.telegram.org/bot{TOKEN}/getUpdates"
                f"?offset={last_update_id + 1}"
            )

            data = requests.get(url, timeout=10).json()

            for update in data.get("result", []):
                last_update_id = update["update_id"]

                message = update.get("message")
                if not message:
                    continue

                text = message.get("text", "")
                chat_id = message["chat"]["id"]

                if text.startswith("/subscribe"):
                    parts = text.split(maxsplit=1)

                    if len(parts) == 2 and parts[1] == SECRET_PASSWORD:
                        store_subscriber(chat_id)
                        print(f"[Telegram] Authorized subscriber {chat_id}")
                    else:
                        print(f"[Telegram] Unauthorized /start attempt from {chat_id}")

                elif text == "/unsubscribe":
                    remove_subscriber(chat_id)
                    print(f"[Telegram] Removed subscriber {chat_id}")

        except Exception as e:
            print(f"[Telegram polling error] {e}")

        time.sleep(2)


def send_telegram_alert(event):
    text = format_event(event)

    targets = get_subscribers()

    for chat_id in targets:
        try:
            requests.post(
                f"https://api.telegram.org/bot{TOKEN}/sendMessage",
                data={
                    "chat_id": chat_id,
                    "text": text
                },
                timeout=5
            )
        except Exception as e:
            print(f"[Telegram send error] {chat_id}: {e}")


def telegram_worker():
    while True:
        event = notification_queue.get()
        try:
            send_telegram_alert(event)
        except Exception as e:
            print(f"[Telegram worker error] {e}")


def format_event(event):
    if not isinstance(event, dict):
        return str(event)

    severity = str(event.get("threatLevel", "INFO")).upper()
    event_type = str(event.get("type", "UNKNOWN"))
    source = str(event.get("source", "unknown"))
    ip = str(event.get("ip", "N/A"))
    message = str(event.get("message", ""))
    timestamp = to_warsaw_time(event.get("timestamp"))

    return (
        "IDS ALERT!\n"
        + "-" * 40 + "\n"
        + f"Severity: {severity}\n"
        + f"Type: {event_type}\n"
        + f"Source: {source}\n"
        + f"IP: {ip}\n"
        + f"Time: {timestamp}\n"
        + "-" * 40 + "\n"
        + f"Details:\n{message}"
    )


def to_warsaw_time(dt):
    if dt is None:
        return "N/A"

    if isinstance(dt, str):
        return dt

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=ZoneInfo("UTC"))

    return dt.astimezone(WARSAW_TZ).strftime("%H:%M:%S %d-%m-%Y")


def start_telegram_system():
    t1 = threading.Thread(target=telegram_polling_loop, daemon=True)
    t2 = threading.Thread(target=telegram_worker, daemon=True)

    t1.start()
    t2.start()