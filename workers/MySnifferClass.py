import multiprocessing
import time
import math
from collections import Counter
from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP, ARP

def shannon_entropy(data: bytes) -> float:
    """Liczy entropię Shannona (0-8) dla bajtów payloadu. Wyższa = bardziej losowe/szyfrowane dane."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())

class MySniffer:
    def __init__(self, interface, analyzer_queue, myIP=None):
        self.analyzer_queue = analyzer_queue
        self.sniffer = AsyncSniffer(
            iface=interface, 
            prn=self.detailed_callback, 
            store=0 
        )
        self.myIP = myIP
        self.sniffer.start()
        print(f"[SNIFFER] Listening on \"{interface}\"... Packets directed straight to the analyzer.")
    
    def __del__(self):
        try:
            self.sniffer.stop()
        except:
            pass

    def detailed_callback(self, packet):
        try:
            # Pobieranie podstawowych cech L2 (Zawsze obecne)
            src_mac = packet.src if hasattr(packet, "src") else None
            dst_mac = packet.dst if hasattr(packet, "dst") else None
            
            # Inicjalizacja domyślna dla L3/L4 (szybsza niż wielokrotne przypisywanie None)
            src_ip, dst_ip, protocol = None, None, "UNKNOWN"
            src_port, dst_port, tcp_flags = None, None, ""
            icmp_type, icmp_code = None, None
            arp_op, arp_psrc, arp_hwsrc = None, None, None
            payload_len = 0
            payload_entropy = 0.0

            # Analiza Warstwy L3 (IP)
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                protocol = "IP" 
                #if self.myIP and (src_ip == self.myIP or dst_ip == self.myIP):
                #    # Ignorujemy ruch, który ma nasz własny adres IP jako źródłowy lub docelowy
                #    return
                if ip_layer.payload:
                    payload_len = len(ip_layer.payload)

                # Analiza Warstwy L4 (TCP / UDP / ICMP)
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    protocol = "TCP"
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport
                    # Krytyczne dla IDS: Wyciągamy flagi jako string (np. "S", "RA", "FPU")
                    tcp_flags = str(tcp_layer.flags)
                    
                elif packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    protocol = "UDP"
                    src_port = udp_layer.sport
                    dst_port = udp_layer.dport
                    
                elif packet.haslayer(ICMP):
                    icmp_layer = packet[ICMP]
                    protocol = "ICMP"
                    # Krytyczne dla IDS: Typ i kod (wykrywanie ICMP Flooding/Smurf/Unreachable scans)
                    icmp_type = icmp_layer.type
                    icmp_code = icmp_layer.code
                    icmp_payload_bytes = bytes(icmp_layer.payload)
                    payload_len = len(icmp_payload_bytes)
                    payload_entropy = shannon_entropy(icmp_payload_bytes)

            elif packet.haslayer(ARP):
                arp_layer = packet[ARP]
                protocol = "ARP"
                arp_op = arp_layer.op
                arp_psrc = arp_layer.psrc
                arp_hwsrc = arp_layer.hwsrc

            data = {
                "packet_time": float(packet.time),
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "src_port": src_port,
                "dst_port": dst_port,
                "tcp_flags": tcp_flags,
                "icmp_type": icmp_type,
                "icmp_code": icmp_code,
                "arp_op": arp_op,
                "arp_psrc": arp_psrc,
                "arp_hwsrc": arp_hwsrc,
                "payload_len": payload_len,
                "payload_entropy": payload_entropy,
                "packet_size": len(packet)
            }

            self.analyzer_queue.put_nowait(data)
            #print(f"[SNIFFER] Catched packet {packet.time}: {data}")

        except Exception as e:
            print(f"[SNIFFER][ERROR] Callback got down on packet {packet.time}: {e}")