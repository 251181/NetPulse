import asyncio
import multiprocessing
import logging
from collections import defaultdict, deque

# Konfiguracja powiadomień IDS
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [IDS ALERT] - %(message)s')

class MyAnalyzer:
    def __init__(self, analyzer_queue: multiprocessing.Queue):
        # Cache do wykrywania ARP Spoofingu: {ip: deque([mac1, mac2], maxlen=2)}
        self.arp_cache = defaultdict(lambda: deque(maxlen=2))

        self.queue = analyzer_queue
        self.running = True
        self.start_loop_task = asyncio.create_task(self.start_loop())

    async def start_loop(self):
        print("[ANALYZER] Uruchomiono asynchroniczny analizator anomalii.")
        logging.warning(f"Analyzer started, waiting for packets...")
        
        while self.running:
            packet_data = await asyncio.to_thread(self.queue.get)
            await self._process_rules(packet_data)

    async def _process_rules(self, pkt: dict):
        proto = pkt.get("protocol")
        flags = pkt.get("tcp_flags", "")
        dst_port = pkt.get("dst_port")

        # --- REGUŁA 1: Wykrywanie skanowania flag TCP (Xmas / Null) ---
        if proto == "TCP":
            # Xmas Scan (FIN, PSH, URG)
            if "F" in flags and "P" in flags and "U" in flags:
                logging.warning(f"XMAS Scan detected from {pkt['src_ip']}:{pkt['src_port']} -> {pkt['dst_ip']}:{pkt['dst_port']}")
            
            # 2. Null Scan Detection (Brak flag)
            elif not flags or flags == "0":
                logging.warning(f"NULL Scan detected from {pkt['src_ip']}:{pkt['src_port']}")
                
            # 3. SYN-FIN Anomaly
            elif "S" in flags and "F" in flags:
                logging.warning(f"Suspicious SYN-FIN packet from {pkt['src_ip']}")

        # --- REGUŁA 2: Podejrzany rozmiar ICMP (Eksfiltracja danych / Tunelowanie) ---
        elif proto == "ICMP":
            payload_len = pkt.get("payload_len", 0)
            payload_entropy = pkt.get("payload_entropy", 0.0) # Skala 0-8 (wyższa = szyfrowane/skompresowane data)
            # Standardowy ping ma mały payload. Duży rozmiar (>300B) z jednego IP to anomalia.
            if payload_len > 200 and payload_entropy > 5.5:
                logging.warning(f"Potential ICMP Tunneling/Data Exfiltration from {pkt['src_ip']}. Payload len: {payload_len}B, Entropy: {payload_entropy}")
        
        elif proto == "ARP":
            # --- REGUŁA 3: ARP Spoofing Detection (Multiple MAC
            op = pkt.get("arp_op")
            psrc = pkt.get("arp_psrc")
            hwsrc = pkt.get("arp_hwsrc")
            
            if op == 2: # ARP Reply
                history = self.arp_cache[psrc]
                if history and history[-1] != hwsrc:
                    logging.critical(f"ARP SPOOFING DETECTED! IP {psrc} moved from {history[-1]} to {hwsrc}")
                    self.arp_cache[psrc].append(hwsrc)

        # --- REGUŁA 4: Krytyczne Porty (Próba dostępu do wrażliwych usług) ---
        # Możesz sprawdzać, czy ktoś nie uderza w porty, które w Twojej sieci korporacyjnej
        # powinny być bezwzględnie zamknięte.
        if dst_port in [21, 22, 23, 445]:  # FTP, SSH, Telnet, SMB
            # Tutaj analizator mógłby wysłać alert do bazy lub powiadomienie do admina
            pass