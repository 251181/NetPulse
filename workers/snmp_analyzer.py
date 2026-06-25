import asyncio
import logging
from datetime import datetime
from collections import defaultdict
from core.event_bus import push_event
from db_tools.db_tools import store_log_async

logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - [SNMP-IDS-ALERT] - %(message)s'
)

class SNMPTelemetryAnalyzer:
    def __init__(self):
        self.states = defaultdict(lambda: {"performance": {}, "interfaces": {}})

    async def analyze_metrics(self, metrics: dict):
        if not metrics or "ip" not in metrics:
            return

        ip = metrics.get("ip")
        perf = metrics.get("performance", {})
        interfaces = metrics.get("interfaces", [])

        await asyncio.gather(
            self._analyze_performance(ip, perf),
            self._analyze_interfaces(ip, interfaces)
        )

    async def _analyze_performance(self, ip: str, perf: dict):
        if not perf:
            return

        prev_perf = self.states[ip]["performance"]

        # REGUŁY DETEKCJI DLA SEKTORA LINUX SERVER
        if "cpu_system" in perf and "cpu_load_1m" in perf:
            try:
                cpu_sys = float(perf["cpu_system"])
                cpu_usr = float(perf["cpu_user"])
                cpu_idle = float(perf["cpu_idle"])
                load_1m = float(perf["cpu_load_1m"])
                total_procs = int(perf["total_processes"])
                tcp_errors = int(perf["tcp_in_errors"])
                
                ram_total = int(perf["ram_total"])
                ram_free = int(perf["ram_free"])
                ram_cached = int(perf.get("ram_cached", 0))
                ram_buffered = int(perf.get("ram_buffered", 0))

                # Stealth / Slow Port Scan
                '''
                if prev_perf and "tcp_in_errors" in prev_perf:
                    prev_tcp_errors = int(prev_perf["tcp_in_errors"])
                    delta_errors = tcp_errors - prev_tcp_errors
                    
                    # Alarm tylko jeśli przyrost błędów > 15 w jednym interwale.
                    # Eliminuje to fałszywe alarmy wywołane naturalnym szumem sieci.
                    if delta_errors > 3 and cpu_idle > 90.0:
                        logging.warning(
                            f"[ATAK: STEALTH PORT SCAN] Host: {ip} | "
                            f"Detected +{delta_errors} rejected/bad TCP packets while CPU is IDLE ({cpu_idle}%). "
                            f"Target is being reconned by low-rate scanner (Total errors: {tcp_errors})."
                        )

                        event = {
                            "timestamp": datetime.utcnow(),
                            "type": "STEALTH_PORT_SCAN",
                            "source": "snmp",
                            "threatLevel": "medium",
                            "ip": ip,
                            "message": (
                                f"The device is receiving an unusual number of rejected network "
                                f"connection attempts (+{delta_errors} in the last interval). "
                                f"This may indicate that someone is scanning the device for open ports."
                            )
                        }
                        push_event(event.copy())

                        try:
                            await store_log_async(event.copy())
                        except Exception:
                            logging.exception("Failed to save log")
                '''
                # Fork-Bomb / Skryptowy DoS
                if total_procs > 300 or load_1m > 12.0:
                    logging.critical(
                        f"[ATAK: FORK-BOMB / RESOURCE EXHAUSTION] Host: {ip} | "
                        f"Table of processes is exploding! Total processes: {total_procs}, Load Average 1m: {load_1m}."
                    )

                    event = {
                        "timestamp": datetime.utcnow(),
                        "type": "RESOURCE_EXHAUSTION",
                        "source": "snmp",
                        "threatLevel": "critical",
                        "ip": ip,
                        "message": (
                            f"The device is running an unusually large number of processes "
                            f"({total_procs} processes, load average: {load_1m:.1f}). "
                            f"This may indicate a resource exhaustion attack or a malfunctioning application.")
                    }

                    push_event(event.copy())

                    try:
                        await store_log_async(event.copy())
                    except Exception:
                        logging.exception("Failed to save log")

                # Agresywny RAM Starvation
                actual_used_ram = ram_total - ram_free - ram_cached - ram_buffered
                ram_utilization_percent = (actual_used_ram / ram_total) * 100
                if ram_utilization_percent > 90.0 or (ram_free + ram_cached) < 55000:
                    swap_changed = False
                    if prev_perf and "swap_free" in prev_perf:
                        swap_changed = int(perf["swap_free"]) < int(prev_perf["swap_free"])
                        
                    logging.critical(
                        f"[ATAK: RESOURCE STARVATION] Host: {ip} | "
                        f"Wykryto maksymalne wysycenie pamięci operacyjnej! "
                        f"Prawdziwe zużycie RAM: {ram_utilization_percent:.2f}% | "
                        f"Fizycznie wolny RAM: {ram_free // 1024}MB, Cache: {ram_cached // 1024}MB. "
                        f"Aktywne swapowanie na dysk: {swap_changed}."
                    )

                    event = {
                        "timestamp": datetime.utcnow(),
                        "type": "RESOURCE_STARVATION",
                        "source": "snmp",
                        "threatLevel": "critical",
                        "ip": ip,
                        "message": (
                            f"The device is running out of memory. "
                            f"RAM usage is {ram_utilization_percent:.1f}% "
                            f"with only {ram_free //  1024} MB of free memory remaining. "
                            f"Disk swapping is currently {'active'  if swap_changed else  'inactive'}. "
                            f"This may indicate a resource exhaustion attack or a malfunctioning application.")
                    }

                    push_event(event.copy())

                    try:
                        await store_log_async(event.copy())
                    except Exception:
                        logging.exception("Failed to save log")

            except (ValueError, TypeError, ZeroDivisionError):
                pass


        # REGUŁY DETEKCJI DLA SEKTORA CISCO (ROUTER / SWITCH)
        elif "cpu_5sec" in perf:
            try:
                cpu_5s = int(perf["cpu_5sec"])
                mem_proc = int(perf["mem_pool_processor_used"])

                # --- KONKRET 1B: Cisco Control Plane Exhaustion (Skalibrowany próg) ---
                if cpu_5s > 60:
                    logging.critical(
                        f"[ATAK: CONTROL PLANE FLOOD] Cisco: {ip} | "
                        f"Router CPU reached critical limit: {cpu_5s}%! Core routing processes are locked."
                    )

                    event = {
                        "timestamp": datetime.utcnow(),
                        "type": "CONTROL_PLANE_EXHAUSTION",
                        "source": "snmp",
                        "threatLevel": "critical",
                        "ip": ip,
                        "message": (
                            f"The network device is under very high processing load. "
                            f"CPU usage has reached {cpu_5s}% on the last measurement. "
                            f"This may affect network stability and cause delays or packet loss.")
                    }

                    push_event(event.copy())

                    try:
                        await store_log_async(event.copy())
                    except Exception:
                        logging.exception("Failed to save log")

                # --- KONKRET 2: Cisco Buffer Overflow / Process Memory Leak ---
                if prev_perf and "mem_pool_processor_used" in prev_perf:
                    prev_mem_proc = int(prev_perf["mem_pool_processor_used"])
                    mem_delta = mem_proc - prev_mem_proc
                    
                    if mem_delta > 12_000_000 and cpu_5s < 15:
                        logging.error(
                            f"[ATAK: ROUTER EXPLOIT / MEMORY LEAK] Cisco: {ip} | "
                            f"Processor memory pool leaked +{mem_delta / 1_000_000:.2f} MB in 10s without CPU activity! "
                            f"Suspected malicious payload causing memory allocation leak."
                        )

                        event = {
                            "timestamp": datetime.utcnow().isoformat() +  "Z",
                            "type": "MEMORY_LEAK_SUSPECTED",
                            "source": "snmp",
                            "threatLevel": "high",
                            "ip": ip,
                            "message": (
                                f"Unusual memory usage increase detected on the device. "
                                f"Processor memory usage has grown by approximately "
                                f"{mem_delta /  1_000_000:.2f} MB in a short period while CPU usage remains low ({cpu_5s}%). "
                                f"This may indicate a memory leak or abnormal process behavior.")
                        }

                        push_event(event.copy())

                        try:
                            await store_log_async(event.copy())
                        except Exception:
                            logging.exception("Failed to save log")

            except (ValueError, TypeError):
                pass

        self.states[ip]["performance"] = perf

    async def _analyze_interfaces(self, ip: str, interfaces: list):
        current_interfaces_state = {}

        for iface in interfaces:
            try:
                if_num = int(iface.get("if_number"))
                if_descr = iface.get("ifDescr", f"Port-{if_num}")
                oper_status = iface.get("ifOperStatus")
                
                out_bytes = int(iface.get("ifOutOctets", 0))
                
                prev_iface = self.states[ip]["interfaces"].get(if_num, {})

                if prev_iface:
                    # ANOMALIA: Link Flapping (Sabotaż / Awaria interfejsu) ---
                    if prev_iface.get("status") != oper_status:
                        logging.warning(
                            f"[ANOMALIA: LINK FLAPPING] Host: {ip} | "
                            f"Interface [{if_descr}] changed operational status from {prev_iface.get('status')} to {oper_status}!"
                        )

                        event = {
                            "timestamp": datetime.utcnow(),
                            "type": "LINK_FLAPPING",
                            "source": "snmp",
                            "threatLevel": "low",
                            "ip": ip,
                            "message": (
                                f"Network interface '{if_descr}' is changing its status frequently. "
                                f"It switched from '{prev_iface.get('status')}' to '{oper_status}'. "
                                f"This may cause temporary network interruptions or instability.")
                        }

                        push_event(event.copy())

                        try:
                            await store_log_async(event.copy())
                        except Exception:
                            logging.exception("Failed to save log")

                    prev_out_bytes = prev_iface.get("out_bytes", 0)
                    delta_out = out_bytes - prev_out_bytes

                    # Eksfiltracja Danych / Tunelowanie (Nienaturalny wzrost ruchu) ---
                    if delta_out > 15_000_000 and "lo" not in if_descr.lower():
                        logging.warning(
                            f"[ATAK: DATA EXFILTRATION DETECTED] Host: {ip} | "
                            f"Anomalous high outbound traffic burst on [{if_descr}]: +{delta_out / 1_000_000:.2f} MB leaving the node!"
                        )

                        event = {
                            "timestamp": datetime.utcnow(),
                            "type": "ANOMALOUS_OUTBOUND_TRAFFIC",
                            "source": "snmp",
                            "threatLevel": "high",
                            "ip": ip,
                            "message": (
                                f"Unusually high outgoing network traffic detected on interface '{if_descr}'. "
                                f"Approximately {delta_out /  1_000_000:.2f} MB of data was sent in a short period. "
                                f"This may indicate large data transfer or possible unauthorized data movement.")
                        }

                        push_event(event.copy())

                        try:
                            await store_log_async(event.copy())
                        except Exception:
                            logging.exception("Failed to save log")

                current_interfaces_state[if_num] = {
                    "status": oper_status,
                    "out_bytes": out_bytes
                }

            except (ValueError, TypeError):
                continue

        self.states[ip]["interfaces"] = current_interfaces_state
