from pymongo import MongoClient
from pprint import pprint

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


def store_packet(packet):
    db.packets.insert_one(packet)


def store_device(ip, general_info=None, performance=None, interfaces=None):
    update = {}

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


def clear_database():
    for name in db.list_collection_names():
        db[name].drop()
