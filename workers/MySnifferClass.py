import multiprocessing
import time
from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP

class MySniffer:
    def __init__(self, interface, analyzer_queue):
        self.analyzer_queue = analyzer_queue
        self.sniffer = AsyncSniffer(
            iface=interface, 
            prn=self.detailed_callback, 
            store=0 
        )
        self.sniffer.start()
        print(f"[SNIFFER] Nasłuchiwanie na \"{interface}\"... Trafia prosto do analizatora.")
    
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
            payload_len = 0

            # Analiza Warstwy L3 (IP)
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                protocol = "IP" 
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
                "payload_len": payload_len,
                "packet_size": len(packet)
            }

            self.analyzer_queue.put_nowait(data)
            #print(f"[SNIFFER] Złapano pakiet: {data}")

        except Exception as e:
            pass