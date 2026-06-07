from scapy.all import ARP, Ether, srp
import netifaces
import socket
import netaddr

def check_interface_families(interface):
    try:
        addr_info = netifaces.ifaddresses(interface)
        
        results = {
            "ipv4": [],
            "ipv6": []
        }

        if socket.AF_INET in addr_info:
            for entry in addr_info[socket.AF_INET]:
                results["ipv4"].append({
                    "ip": entry['addr'],
                    "mask": entry['netmask']
                })

        if socket.AF_INET6 in addr_info:
            for entry in addr_info[socket.AF_INET6]:
                results["ipv6"].append({
                    "ip": entry['addr'],
                    "mask": entry.get('netmask') # IPv6 uses netmask/prefix
                })
        print(f'Found IPs on this interface: {results}')
        return results

    except ValueError:
        return f"Error: Interface {interface} not found."


def scanForDevices(interface):
    print("[*] Rozpoczynam jednorazowe skanowanie sieci...")
    status = check_interface_families(interface)
    clients = []

    scanned_networks = set()

    if status['ipv4']:
        for item in status['ipv4']:
            ip_addr = item['ip']
            netmask = item['mask']
            
            network = netaddr.IPNetwork(f"{ip_addr}/{netmask}")
            network_cidr = str(network.cidr)

            if network_cidr not in scanned_networks:
                print(f"Scanning new network: {network_cidr} via {ip_addr}")
                clients += ARPscan(interface, ip_addr, netmask)
                scanned_networks.add(network_cidr)
            else:
                print(f"Skipping {ip_addr} - network {network_cidr} already scanned.")

    print(f"[*] Zakończono skanowanie sieci. Znaleziono {len(clients)} urządzeń.")
    return clients

def ARPscan(interface, ip_addr, netmask):
    network = netaddr.IPNetwork(f"{ip_addr}/{netmask}")

    cidr_suffix = f"/{network.prefixlen}"

    target_ip = ip_addr+cidr_suffix

    arp = ARP(pdst=target_ip)

    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0, iface=interface)[0]

    clients = []

    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    return clients

def printDevices(devices):
    print("Available devices in the network:")
    print("IP" + " "*18+"MAC")
    for client in devices:
        print("{:16}    {}".format(client['ip'], client['mac']))