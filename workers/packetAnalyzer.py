import asyncio
import multiprocessing
import logging
from collections import defaultdict, deque
from core.event_bus import push_event
from db_tools.db_tools import store_log_async
from datetime import datetime
import time
import ipaddress

# Konfiguracja powiadomień IDS
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [IDS ALERT] - %(message)s')

class MyAnalyzer:
    def __init__(self, analyzer_queue: multiprocessing.Queue, safe_network: ipaddress.IPv4Network):
        # Cache do wykrywania ARP Spoofingu: {ip: deque([mac1, mac2], maxlen=2)}
        self.arp_cache = defaultdict(lambda: deque(maxlen=2))

        self.queue = analyzer_queue
        self.running = True
        self.safe_network = safe_network
        self.start_loop_task = asyncio.create_task(self.start_loop())

        self.moving_average_detector = MovingAverageDetector()
        self.structural_anomaly_detector = StructuralAnomalyDetector()

    async def start_loop(self):
        print("[PACKET ANALYZER] Uruchomiono asynchroniczny analizator anomalii.")
        logging.warning(f"Analyzer started, waiting for packets...")
        
        loop_task_structural = asyncio.create_task(self.structural_anomaly_detector.analysis_loop())
        loop_task_moving_avg = asyncio.create_task(self.moving_average_detector.check_anomaly())

        try:
            # Główna pętla zbierania pakietów
            while self.running:
                packet_data = await asyncio.to_thread(self.queue.get)
                try:
                    await self._process_rules(packet_data)
                except Exception:
                    logging.exception(f"Error processing packet: {packet_data}")
                    
        except asyncio.CancelledError:
            logging.info("Główna pętla analizatora została zatrzymana.")
            
        finally:
            print("[PACKET ANALYZER] Zamykanie zadań detekcji anomalii...")
            loop_task_structural.cancel()
            loop_task_moving_avg.cancel()
            

    async def _process_rules(self, pkt: dict):
        self.moving_average_detector.register_packet()
        self.structural_anomaly_detector.process_tcp_metrics(pkt['src_ip'], pkt['dst_ip'], pkt.get('tcp_flags', ''), protocol=pkt.get('protocol', 'UNKNOWN'))
        
        proto = pkt.get("protocol")
        flags = pkt.get("tcp_flags", "")
        dst_port = pkt.get("dst_port")

        # Wykrywanie skanowania flag TCP (Xmas / Null) ---
        if proto == "TCP":
            # Xmas Scan (FIN, PSH, URG)
            if "F" in flags and "P" in flags and "U" in flags:
                logging.warning(f"XMAS Scan detected from {pkt['src_ip']}:{pkt['src_port']} -> {pkt['dst_ip']}:{pkt['dst_port']}")
            
                event = {
                    "timestamp": datetime.utcnow(),
                    "type": "TCP_XMAS_SCAN",
                    "source": "packet_analysis",
                    "threatLevel": "high",
                    "ip": pkt["dst_ip"],
                    "message": (
                        f"XMAS scan detected targeting {pkt['dst_ip']}:{pkt['dst_port']} "
                        f"from {pkt['src_ip']}:{pkt['src_port']}. "
                        f"TCP packet has FIN, PSH, and URG flags set simultaneously, "
                        f"which is commonly used for stealth port scanning and network reconnaissance."
                    )
                }

                push_event(event.copy())

                try:
                    await store_log_async(event.copy())
                except Exception:
                    logging.exception("Failed to save log")
            
            # 2. Null Scan Detection (Brak flag)
            elif not flags or flags == "0":
                logging.warning(f"NULL Scan detected from {pkt['src_ip']}:{pkt['src_port']}")

                event = {
                    "timestamp": datetime.utcnow(),
                    "type": "TCP_NULL_SCAN",
                    "source": "packet_analysis",
                    "threatLevel": "high",
                    "ip": pkt["dst_ip"],
                    "message": (
                        f"NULL scan detected targeting {pkt['dst_ip']}:{pkt['dst_port']} "
                        f"from {pkt['src_ip']}:{pkt['src_port']}. "
                        f"TCP packet was sent with no flags set, which is commonly used "
                        f"for stealth port scanning and reconnaissance of firewall rules."
                    )
                }

                push_event(event.copy())

                try:
                    await store_log_async(event.copy())
                except Exception:
                    logging.exception("Failed to save log")
                
            # 3. SYN-FIN Anomaly
            elif "S" in flags and "F" in flags:
                logging.warning(f"Suspicious SYN-FIN packet from {pkt['src_ip']}")

                event = {
                    "timestamp": datetime.utcnow(),
                    "type": "TCP_SYN_FIN_ANOMALY",
                    "source": "packet_analysis",
                    "threatLevel": "high",
                    "ip": pkt["dst_ip"],
                    "message": (
                        f"SYN-FIN anomaly detected targeting {pkt['dst_ip']}:{pkt['dst_port']} "
                        f"from {pkt['src_ip']}:{pkt['src_port']}. "
                        f"TCP packet contains both SYN and FIN flags, which is not valid "
                        f"in normal communication and may indicate stealth scanning or packet manipulation."
                    )
                }

                push_event(event.copy())

                try:
                    await store_log_async(event.copy())
                except Exception:
                    logging.exception("Failed to save log")

        # Podejrzany rozmiar ICMP (Eksfiltracja danych / Tunelowanie) ---
        elif proto == "ICMP":
            payload_len = pkt.get("payload_len", 0)
            payload_entropy = pkt.get("payload_entropy", 0.0) # Skala 0-8 (wyższa = szyfrowane/skompresowane data)
            # Standardowy ping ma mały payload. Duży rozmiar (>300B) z jednego IP to anomalia.
            if payload_len > 200 and payload_entropy > 5.5:
                logging.warning(f"Potential ICMP Tunneling/Data Exfiltration from {pkt['src_ip']}. Payload len: {payload_len}B, Entropy: {payload_entropy}")
        
                event = {
                    "timestamp": datetime.utcnow(),
                    "type": "ICMP_TUNNELING_SUSPECTED",
                    "source": "packet_analysis",
                    "threatLevel": "high",
                    "ip": pkt["dst_ip"],
                    "message": (
                        f"Potential ICMP tunneling or data exfiltration detected targeting {pkt['dst_ip']}. "
                        f"Packet originated from {pkt['src_ip']}. "
                        f"Unusually large ICMP payload detected ({payload_len} bytes) with high entropy "
                        f"({payload_entropy:.2f}/8 scale), which suggests encoded or encrypted data transfer "
                        f"over ICMP protocol instead of normal ping traffic."
                    )
                }

                push_event(event.copy())

                try:
                    await store_log_async(event.copy())
                except Exception:
                    logging.exception("Failed to save log")

        elif proto == "ARP":
            # ARP Spoofing Detection (Multiple MAC)
            op = pkt.get("arp_op")
            psrc = pkt.get("arp_psrc")
            hwsrc = pkt.get("arp_hwsrc")
            
            if op == 2: # ARP Reply
                history = self.arp_cache[psrc]
                if history and history[-1] != hwsrc:
                    logging.critical(f"ARP SPOOFING DETECTED! IP {psrc} moved from {history[-1]} to {hwsrc}")

                    event = {
                        "timestamp": datetime.utcnow(),
                        "type": "ARP_SPOOFING_DETECTED",
                        "source": "packet_analysis",
                        "threatLevel": "critical",
                        "ip": psrc,
                        "message": (
                            f"ARP spoofing detected for IP {psrc}. "
                            f"MAC address changed from {history[-1]} to {hwsrc}. "
                            f"Packet originated from ARP reply operation indicating possible "
                            f"man-in-the-middle attempt or local network impersonation attack."
                        )
                    }

                    push_event(event.copy())

                    try:
                        await store_log_async(event.copy())
                    except Exception:
                        logging.exception("Failed to save log")

                self.arp_cache[psrc].append(hwsrc) # zawsze zapisuj, nie tylko gdy wykryto spoofing

        # Krytyczne Porty (Próba dostępu do wrażliwych usług) ---
        if dst_port in [21, 22, 23, 445]:  # FTP, SSH, Telnet, SMB
            try:
                src_ip_obj = ipaddress.ip_address(pkt['src_ip'])
                is_local = src_ip_obj in self.safe_network
            except ValueError:
                # Na wypadek, gdyby src_ip był None lub błędnym adresem
                is_local = False

            if is_local:
                return  # Ignorujemy ruch z lokalnej sieci

            logging.warning(f"Suspicious access to critical port {dst_port} from {pkt['src_ip']}")
            
            event = {
                "timestamp": datetime.utcnow(),
                "type": "SUSPICIOUS_CRITICAL_PORT_ACCESS",
                "source": "packet_analysis",
                "threatLevel": "medium",
                "ip": pkt["dst_ip"],
                "message": (
                    f"Suspicious connection attempt detected on critical service port {dst_port} "
                    f"targeting {pkt['dst_ip']}:{dst_port} from {pkt['src_ip']}:{pkt['src_port']}. "
                    f"These ports are commonly used by FTP, SSH, Telnet, and SMB services, "
                    f"which are frequent targets for brute-force attacks and unauthorized access attempts."
                )
            }

            push_event(event.copy())

            try:
                await store_log_async(event.copy())
            except Exception:
                logging.exception("Failed to save log")

from collections import deque

class MovingAverageDetector:
    def __init__(self, long_window_sec=300, short_window_sec=5, multiplier=20.0):
        self.long_window_sec = long_window_sec
        self.short_window_sec = short_window_sec
        self.multiplier = multiplier
        self.anti_alert_spam = 0
        
        self.long_history = deque()
        self.short_history = deque()

    def register_packet(self):
        now = time.time()
        self.long_history.append(now)
        self.short_history.append(now)

    async def check_anomaly(self):
        while True:
            await asyncio.sleep(1)
            now = time.time()

            while self.long_history and self.long_history[0] < now - self.long_window_sec:
                self.long_history.popleft()
            while self.short_history and self.short_history[0] < now - self.short_window_sec:
                self.short_history.popleft()

            avg_long_pps = len(self.long_history) / self.long_window_sec
            avg_short_pps = len(self.short_history) / self.short_window_sec
        
            if (not self.anti_alert_spam) and (avg_long_pps > 5 and avg_short_pps > (avg_long_pps * self.multiplier)):
                print(f"[ALERT] Wolumetryczny DoS! Obecny PPS: {avg_short_pps:.1f} "
                      f"jest > {self.multiplier}x większy niż norma ({avg_long_pps:.1f} PPS)")

                event = {
                    "timestamp": datetime.utcnow(),
                    "type": "VOLUMETRIC_DDOS_DETECTED",
                    "source": "packet_analysis",
                    "threatLevel": "high",
                    "ip": "0.0.0.0",
                    "message": (
                        f"Volumetric traffic anomaly detected. "
                        f"Current traffic rate is {avg_short_pps:.1f} PPS, "
                        f"which exceeds the baseline rate of {avg_long_pps:.1f} PPS "
                        f"by a factor of {self.multiplier:.2f}. "
                        f"This indicates a sudden surge in network traffic volume, "
                        f"which may represent a distributed denial-of-service attack or burst traffic event."
                    )
                }

                push_event(event.copy())

                try:
                    await store_log_async(event.copy())
                except Exception:
                    logging.exception("Failed to save log")
                
                self.anti_alert_spam = 1  # Resetujemy, by nie spamować alertami co sekundę
            elif not (avg_long_pps > 5 and avg_short_pps > (avg_long_pps * self.multiplier)):
                self.anti_alert_spam = 0  # Resetujemy, gdy sytuacja wraca do normy

class StructuralAnomalyDetector:
    def __init__(self, max_syn_ack_ratio=5.0, max_unique_ip_ratio=0.7):
        self.max_syn_ack_ratio = max_syn_ack_ratio
        self.max_unique_ip_ratio = max_unique_ip_ratio
        self.SYNACK1_anti_alert_spam = 0
        self.SYNACK2_anti_alert_spam = 0
        self.unique_ip_anti_alert_spam = 0
        
        self.syn_count = 0
        self.ack_count = 0
        self.total_packets = 0
        self.unique_src_ips = set()

    def process_tcp_metrics(self, src_ip, dst_ip, tcp_flags_str, protocol):
        if not src_ip or protocol != "TCP":
            return
            
        self.total_packets += 1
        self.unique_src_ips.add(src_ip)
        if tcp_flags_str:
            if "S" in tcp_flags_str:  
                self.syn_count += 1
            if "A" in tcp_flags_str:  
                self.ack_count += 1

    async def analysis_loop(self, interval_sec=5):
        while True:
            await asyncio.sleep(interval_sec)
            
            if self.total_packets == 0:
                continue

            current_syn = self.syn_count
            current_ack = self.ack_count
            current_total = self.total_packets
            current_unique = len(self.unique_src_ips)

            self.syn_count = 0
            self.ack_count = 0
            self.total_packets = 0
            self.unique_src_ips.clear()

            if current_ack == 0:
                ratio = float('inf')
            else:
                ratio = current_syn / current_ack

            if current_syn < 150: 
                # Ruch jest zbyt mały, by zagrażał sieci - traktujemy jako normalne falowanie
                continue

            # ratio jest wysokie (klasyczny, czysty flood lub "cichy" atak)
            if ratio > self.max_syn_ack_ratio and current_syn >= 150:
                if self.SYNACK1_anti_alert_spam:
                    continue
                print(f"[ALERT] Wykryto DoS typu SYN Flood (Asymetria flag serwer nie wyrabia)! SYN/ACK Ratio = {ratio:.2f}")
                
                event = {
                    "timestamp": datetime.utcnow(),
                    "type": "SYN_FLOOD_DETECTED",
                    "source": "packet_analysis",
                    "threatLevel": "high",
                    "ip": "0.0.0.0",
                    "message": (
                        f"A possible SYN Flood attack has been detected. "
                        f"The observed SYN/ACK ratio is {ratio:.2f}, "
                        f"with {current_syn} SYN packets recorded during the "
                        f"monitoring interval. "
                        f"This indicates that the server may be receiving "
                        f"a large number of connection requests without "
                        f"corresponding acknowledgements, which can lead to "
                        f"resource exhaustion and denial of service."
                    )
                }

                push_event(event.copy())

                try:
                    await store_log_async(event.copy())
                except Exception:
                    logging.exception("Failed to save log")

                self.SYNACK1_anti_alert_spam = 1

            # ratio jest niskie (bo serwer daje rade odpowiadac), 
            elif current_syn > 500:
                if self.SYNACK2_anti_alert_spam:
                    continue
                print(f"[ALERT] Wykryto DoS typu SYN Flood (Agresywny wolumen)! "
                    f"Ratio w normie ({ratio:.2f}), bo serwer próbuje się bronić, "
                    f"ale wykryto aż {current_syn} pakietów SYN w ciągu 5 sekund!")
                    
                event = {
                    "timestamp": datetime.utcnow(),
                    "type": "SYN_FLOOD_HIGH_VOLUME",
                    "source": "packet_analysis",
                    "threatLevel": "high",
                    "ip": "0.0.0.0",
                    "message": (
                        f"A high-volume SYN Flood attack may be in progress. "
                        f"The detector observed {current_syn} SYN packets "
                        f"during the last 5-second interval. "
                        f"Although the SYN/ACK ratio remains within normal "
                        f"limits ({ratio:.2f}), the unusually high number of "
                        f"connection requests suggests an aggressive flood of "
                        f"TCP SYN packets that may exhaust network or server "
                        f"resources."
                    )
                }

                push_event(event.copy())

                try:
                    await store_log_async(event.copy())
                except Exception:
                    logging.exception("Failed to save log")

                self.SYNACK2_anti_alert_spam = 1

            if not (ratio > self.max_syn_ack_ratio and current_syn >= 150):
                self.SYNACK1_anti_alert_spam = 0 
            if not (current_syn > 500):
                self.SYNACK2_anti_alert_spam = 0 

            # Jeśli dodatkowo w strukturze bierze udział wiele unikalnych IP
            ip_dispersion_ratio = current_unique / current_total
            if ip_dispersion_ratio > self.max_unique_ip_ratio and current_total > 500:
                if self.unique_ip_anti_alert_spam:
                    continue
                print(f"[ALERT] Wykryto ROZPROSZONY DDoS! Unikalne adresy IP stanowią "
                      f"{ip_dispersion_ratio*100:.1f}% całego ruchu (Total: {current_total} pkt).")
                
                event = {
                    "timestamp": datetime.utcnow(),
                    "type": "DISTRIBUTED_DENIAL_OF_SERVICE",
                    "source": "packet_analysis",
                    "threatLevel": "critical",
                    "ip": ip,
                    "message": (
                        f"Potential distributed denial-of-service attack detected against the device. "
                        f"Unique source IP addresses accounted for {ip_dispersion_ratio * 100:.1f}% "
                        f"of the observed traffic during the monitoring interval, with a total of "
                        f"{current_total} packets captured. This high level of source diversity "
                        f"indicates that the traffic may originate from multiple coordinated hosts "
                        f"or a botnet."
                    )
                }

                push_event(event.copy())

                try:
                    await store_log_async(event.copy())
                except Exception:
                    logging.exception("Failed to save log")

                self.unique_ip_anti_alert_spam = 1
            else:
                self.unique_ip_anti_alert_spam = 0