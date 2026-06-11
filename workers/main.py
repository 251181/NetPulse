from scapy.all import get_if_list, get_if_addr
import time
import asyncio
import multiprocessing

from workers.MySnifferClass import MySniffer
from workers.SubnetScanner import scanForDevices
from workers.PollerManager import PollerManager
from workers.SnmpPoller import AsyncSNMPPoller
from workers.packetAnalyzer import MyAnalyzer
from workers.snmp_analyzer import SNMPTelemetryAnalyzer

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
    interface_SNMP, interface_PM = getInterfaceFromUser()
    
    shared_queue = multiprocessing.Queue()

    mySniffer = MySniffer(interface_PM, shared_queue, myIP=get_if_addr(interface_PM))
    analyzer = MyAnalyzer(shared_queue)
    #asyncio.run(analyzer.start_loop())

    poller = AsyncSNMPPoller()
    snmp_analyzer = SNMPTelemetryAnalyzer()

    raw_hosts = scanForDevices(interface_SNMP) # ARP Scan

    await PollerManager().load_lookup_table("/home/AdminNetPulse/NetPulseApp/workers/devices.json")

    monitored_devices = await PollerManager().poll_devices(poller, raw_hosts)

    # pętla główna programu
    while True:
        print("Updating monitored devices and polling SNMP metrics...")
        await PollerManager().poll_metrics(poller, snmp_analyzer)
        await asyncio.sleep(10) # Interwał odpytywania


def main():
    try:
        asyncio.run(start_app())
    except KeyboardInterrupt:
        print("\nZamykanie NetPulse...")