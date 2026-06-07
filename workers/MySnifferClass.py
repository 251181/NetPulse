from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, AsyncSniffer, raw
#from db_tools import store_packet_in_db

class MySniffer:
    def __init__(self, interface, cursor, db):
        self.cursor = cursor
        self.db = db
        self.sniffer = AsyncSniffer(
            iface=interface, 
            prn=self.detailed_callback, 
            store=0
        )
        self.sniffer.start()
        print(f"Sniffing on \"{interface}\"... Press Ctrl+C to stop.")
    
    def __del__(self):
        self.sniffer.stop()

    def detailed_callback(self, packet):
        src_mac = None
        dst_mac = None
        src_ip = None
        dst_ip = None
        protocol = None
        src_port = None
        dst_port = None
        packet_size = len(packet) 
        payload = None

        if hasattr(packet, "src") and hasattr(packet, "dst"):
            src_mac = packet.src
            dst_mac = packet.dst

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = "IP" 

        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            # ICMP nie ma portów, zostaną jako None (w bazie jako NULL)

        if packet.haslayer(IP) and packet[IP].payload:
            # raw() zamienia payload na obiekt typu bytes
            payload = raw(packet[IP].payload)

        self.save_to_db(src_mac, dst_mac, src_ip, dst_ip, protocol, src_port, dst_port, packet_size, payload, packet.time)

    def save_to_db(self, src_mac, dst_mac, src_ip, dst_ip, protocol, src_port, dst_port, packet_size, payload, timestamp):
        #values = (timestamp, src_mac, dst_mac, src_ip, dst_ip, protocol, src_port, dst_port, packet_size, payload)
        #store_packet_in_db(self.db, self.cursor, values)
        pass