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
        pprint(packet)
        print("-" * 40)

    if count == 0:
        print("No packets found.")


def display_routers():
    routers = db.routers.find()

    count = 0

    print("\n=== ROUTERS LIST ===\n")

    for router in routers:
        count += 1
        print(f"[{count}]")
        pprint(router)
        print("-" * 40)

    if count == 0:
        print("No routers found.")


def display_hosts():
    hosts = db.hosts.find()

    count = 0

    print("\n=== HOSTS LIST ===\n")

    for host in hosts:
        count += 1
        print(f"[{count}]")
        pprint(host)
        print("-" * 40)

    if count == 0:
        print("No hosts found.")


def store_packet(packet):
    db.packets.insert_one(packet)


def store_router(router):
    db.routers.update_one(
        {"ip_address": router["ip_address"]},
        {"$set": router},
        upsert=True
    )


def store_host(host):
    db.hosts.insert_one(host)


def clear_database():
    for name in db.list_collection_names():
        db[name].drop()
