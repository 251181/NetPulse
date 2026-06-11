from pymongo import MongoClient
from pprint import pprint
from datetime import datetime, timezone
import asyncio

client = MongoClient("mongodb://localhost:27017")
db = client["NetPulse"]


def display_packets():
    packets = db.packets.find()

    count = 0

    print("\n=== PACKETS LIST ===\n")

    for packet in packets:
        count += 1
        print(f"[{count}]")
        print(datetime.fromtimestamp(packet["packet_time"]))
        pprint(packet)
        print("-" * 40)

    if count == 0:
        print("No packets found.")


def display_devices():
    devices = db.devices.find()

    count = 0

    print("\n=== DEVICES LIST ===\n")

    for device in devices:
        count += 1
        print(f"[{count}]")
        pprint(device)
        print("-" * 40)

    if count == 0:
        print("No devices found.")


def display_logs():
    logs = db.logs.find()

    count = 0

    print("\n=== LOGS LIST ===\n")

    for log in logs:
        count += 1
        print(f"[{count}]")
        pprint(log)
        print("-" * 40)

    if count == 0:
        print("No logs found.")


def display_metrics():
    metrics = db.metrics.find()

    count = 0

    print("\n=== METRICS LIST ===\n")

    for metric in metrics:
        count += 1
        print(f"[{count}]")
        pprint(metric)
        print("-" * 40)

    if count == 0:
        print("No metrics found.")


def display_subscribers():
    subscribers = db.telegram_subscribers.find()

    count = 0

    print("\n=== METRICS LIST ===\n")

    for subscriber in subscribers:
        count += 1
        print(f"[{count}]")
        pprint(subscriber)
        print("-" * 40)

    if count == 0:
        print("No subscribers found.")


def store_packet(packet):
    db.packets.insert_one(packet)


def store_device(ip, general_info=None, performance=None, interfaces=None):
    update = {"last_seen": datetime.now(timezone.utc)}

    if general_info is not None:
        general_info = general_info.copy()
        general_info.pop('ip', None)
        update["general_info"] = general_info

    if performance is not None:
        update["performance"] = performance

    if interfaces is not None:
        update["interfaces"] = interfaces

    db.devices.update_one(
        {"ip": ip},
        {
            "$set": update,
            "$setOnInsert": {"ip": ip}
        },
        upsert=True
    )


def store_log(log):
    db.logs.insert_one(log)


async def store_log_async(log):
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, store_log, log)


def build_metrics(ip, performance, interfaces):
    metrics = {
        "ip": ip,
        "timestamp": datetime.now(timezone.utc),

        "cpu": None,
        "ram": None,

        "rx_bytes": 0,
        "tx_bytes": 0,
        "rx_packets": 0,
        "tx_packets": 0,

        "interfaces_up": 0,
        "interfaces_down": 0
    }

    if performance:
        try:
            if "cpu_1min" in performance:
                cpu = float(performance["cpu_1min"])
            elif "cpu_idle" in performance:
                cpu = 100.0 - float(performance["cpu_idle"])
            else:
                cpu = None

            if cpu is not None:
                metrics["cpu"] = cpu

        except:
            pass

    if performance:
        try:
            if "ram_total" in performance:
                total = float(performance.get("ram_total", 0))
                free = float(performance.get("ram_free", 0))
                cached = float(performance.get("ram_cached", 0))
                buffered = float(performance.get("ram_buffered", 0))

                metrics["ram"] = total - free - cached - buffered

            elif ("mem_pool_processor_used" in performance
                  or "mem_pool_io_used" in performance):

                proc = float(performance.get("mem_pool_processor_used", 0))
                io = float(performance.get("mem_pool_io_used", 0))

                metrics["ram"] = proc + io

        except:
            pass

    if interfaces:
        for iface in interfaces:
            try:
                oper = str(iface.get("ifOperStatus", "0"))

                if oper == "1":
                    metrics["interfaces_up"] += 1
                else:
                    metrics["interfaces_down"] += 1

                metrics["rx_bytes"] += int(iface.get("ifInOctets", 0))
                metrics["tx_bytes"] += int(iface.get("ifOutOctets", 0))

                metrics["rx_packets"] += int(iface.get("ifInUcastPkts", 0))
                metrics["tx_packets"] += int(iface.get("ifOutUcastPkts", 0))

            except:
                continue

    return metrics

def store_metrics(metrics):
    db.metrics.insert_one(metrics)


def store_subscriber(chat_id):
    db.telegram_subscribers.update_one(
        {"chat_id": chat_id},
        {"$set": {"chat_id": chat_id}},
        upsert=True
    )


def get_subscribers():
    return [doc["chat_id"] for doc in db.telegram_subscribers.find({}, {"chat_id": 1})]


def remove_subscriber(chat_id: int):
    db.telegram_subscribers.delete_one({"chat_id": chat_id})


def clear_database():
    for name in db.list_collection_names():
        db[name].drop()
