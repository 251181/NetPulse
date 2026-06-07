from scapy.all import get_if_list, get_if_addr
import time
import asyncio

import MySnifferClass
import SubnetScanner
from PollerManager import PollerManager
from SnmpPoller import AsyncSNMPPoller

#from db_tools import connect_to_db

monitored_devices = {}

    # Run with sudo!

def getInterfaceFromUser():
    print("Available interfaces:")
    for interface in get_if_list():
        print(f"{interface}, with addr: {get_if_addr(interface)}")

    print("Provide network interface for SNMP ", end="")
    while(True):
        interface_SNMP = input("[virbr0]: ") or "virbr0"
        if interface_SNMP not in get_if_list():
            print(f"Error: Interface \"{interface_SNMP}\" does not exist, try again: ", end="")
        else:
            break

    print("Provide network interface for Port Mirroring ", end="")
    while(True):
        interface_PM = input("[tap-span]: ") or "tap-span"
        if interface_PM not in get_if_list():
            print(f"Error: Interface \"{interface_PM}\" does not exist, try again: ", end="")
        else:
            break

    return interface_SNMP, interface_PM

async def start_app():
    #db, cursor = connect_to_db()
    db = None
    cursor = None

    interface_SNMP, interface_PM = getInterfaceFromUser()
    
    mySniffer = MySnifferClass.MySniffer(interface_PM, cursor, db)
    poller = AsyncSNMPPoller()

    raw_hosts = SubnetScanner.scanForDevices(interface_SNMP) # ARP Scan

    await PollerManager().load_lookup_table("devices.json")

    monitored_devices = await PollerManager().poll_devices(poller, raw_hosts)

    print("Monitoring the following devices:")
    for device in monitored_devices.values():
        print(f" - {device}")

    # pętla główna programu
    while True:
        print("test3")
        await PollerManager().poll_metrics(poller)
        await asyncio.sleep(30) # Interwał odpytywania


if __name__ == "__main__":
    try:
        asyncio.run(start_app())
    except KeyboardInterrupt:
        print("\nZamykanie NetPulse...")