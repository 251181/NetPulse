import asyncio
from pysnmp.hlapi.asyncio import (
    SnmpEngine, 
    CommunityData, 
    UdpTransportTarget, 
    ContextData, 
    ObjectType, 
    ObjectIdentity, 
    get_cmd
)

# --- KONFIGURACJA UNIWERSALNA ---
OIDS = {
    # Używane TYLKO podczas fazy Discovery (init), aby nie przeciążać pętli telemetrycznej
    "base": {
        "sysDescr": "1.3.6.1.2.1.1.1.0", 
        "sysName": "1.3.6.1.2.1.1.5.0",
        "sysServices": "1.3.6.1.2.1.1.7.0"
    },
    
    # Metryki wydajnościowe i detekcji anomalii (Odpytywane cyklicznie co interwał)
    "performance": {
        "Cisco IOS/Nexus": {
            # CPU
            "cpu_5sec": "1.3.6.1.4.1.9.9.109.1.1.1.1.3.1",    
            "cpu_1min": "1.3.6.1.4.1.9.9.109.1.1.1.1.4.1",    
            "cpu_5min": "1.3.6.1.4.1.9.9.109.1.1.1.1.5.1",    
            
            # Pamięć RAM i Pule
            "mem_pool_processor_used": "1.3.6.1.4.1.9.9.48.1.1.1.5.1", 
            "mem_pool_io_used": "1.3.6.1.4.1.9.9.48.1.1.1.5.2",        
        },
        
        "Linux/Unix Server": {
            # Obciążenie systemu (Load Average)
            "cpu_load_1m": "1.3.6.1.4.1.2021.10.1.3.1",    
            "cpu_load_5m": "1.3.6.1.4.1.2021.10.1.3.2",    
            
            # Detekcja DDoS na poziomie Kernela (System vs User)
            "cpu_user": "1.3.6.1.4.1.2021.11.9.0",         # CPU dla aplikacji (%)
            "cpu_system": "1.3.6.1.4.1.2021.11.10.0",       # CPU dla Kernela (%) - KLUCZOWE PRZY DDoS
            "cpu_idle": "1.3.6.1.4.1.2021.11.11.0",         # Wolny procesor (%)
            
            # Pamięć RAM i SWAP (Wykrywanie Memory Leak / Buffer Overflow)
            "ram_total": "1.3.6.1.4.1.2021.4.5.0",         
            "ram_free": "1.3.6.1.4.1.2021.4.6.0",          
            "ram_cached": "1.3.6.1.4.1.2021.4.13.0",       
            "ram_buffered": "1.3.6.1.4.1.2021.4.14.0",     
            "swap_total": "1.3.6.1.4.1.2021.4.3.0",        
            "swap_free": "1.3.6.1.4.1.2021.4.4.0",         
            
            # Przestrzeń dyskowa i procesy (Wykrywanie Fork-Bomb / Ransomware)
            "total_processes": "1.3.6.1.2.1.25.1.6.0",       # Liczba uruchomionych procesów (hrSystemProcesses)
            "tcp_in_errors": "1.3.6.1.2.1.6.12.0"            # Licznik uszkodzonych pakietów TCP (tcpInErrs)
        }
    },
    
    # Statystyki interfejsów sieciowych (Mierzone per-port dynamicznie)
    "interfaces": {
        "ifNumber": "1.3.6.1.2.1.2.1.0",              
        "ifDescr": "1.3.6.1.2.1.2.2.1.2",             
        "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",         
        
        # Liczniki wolumetryczne (Bity/Bajty)
        "ifInOctets": "1.3.6.1.2.1.2.2.1.10",         # Całkowity ruch wejściowy (Bajty)
        "ifOutOctets": "1.3.6.1.2.1.2.2.1.16",        # Całkowity ruch wyjściowy (Bajty)
        
        # Liczniki pakietowe (Kluczowe przy Floodzie małych pakietów, np. 64B SYN Flood)
        "ifInUcastPkts": "1.3.6.1.2.1.2.2.1.11",       # Pakiety unicast odebrane (Szybki skok = PPS flood)
        "ifOutUcastPkts": "1.3.6.1.2.1.2.2.1.17",      # Pakiety unicast wysłane
        
        # Liczniki błędów (Przepełnienia buforów kart sieciowych / Uszkodzone ramki L2)
        "ifInErrors": "1.3.6.1.2.1.2.2.1.14",          # Błędy wejściowe interfejsu (Dropowanie przez przepełnienie)
        "ifOutErrors": "1.3.6.1.2.1.2.2.1.20"          # Błędy wyjściowe interfejsu
    }
}

VENDOR_MAP = {
    "Cisco": "Cisco IOS/Nexus",
    "NX-OS": "Cisco Nexus",
    "Linux": "Linux/Unix Server",
    "MikroTik": "MikroTik RouterOS",
    "Windows": "Windows Server",
    "Huawei": "Huawei VRP Platform",
    "Juniper": "Juniper Junos"
}

class AsyncSNMPPoller:
    def __init__(self, communities=['public', 'cisco', 'admin'], port=161, timeout=2, retries=1):
        self.communities = communities
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self.engine = SnmpEngine()
        self.auth_cache = {}  

    async def get_device_identity(self, ip):
        """Discovery rozbudowane o zliczanie liczby interfejsów (ifNumber) i sysServices."""
        for community in self.communities:
            response = await self._try_query(ip, community)
            if response:
                self.auth_cache[ip] = {
                    'community': community,
                    'transport': response['transport']
                }
                vendor = self._identify_vendor(response['sysDescr'])
                
                try:
                    if_count = int(response.get('ifNumber', 0))
                except ValueError:
                    if_count = 0

                return {
                    'ip': ip,
                    'status': 'up',
                    'vendor': vendor,
                    'community': community,
                    'sysName': response['sysName'],
                    'sysDescr': response['sysDescr'],
                    'sysServices': response.get('sysServices', '0'),
                    'ifNumber': if_count  
                }
        return {'ip': ip, 'status': 'down'}

    async def _try_query(self, ip, community):
        try:
            transport = await UdpTransportTarget.create(
                (ip, self.port), 
                timeout=self.timeout, 
                retries=self.retries
            )
            
            errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
                self.engine,
                CommunityData(community, mpModel=1),
                transport,
                ContextData(),
                ObjectType(ObjectIdentity(OIDS["base"]["sysName"])),
                ObjectType(ObjectIdentity(OIDS["base"]["sysDescr"])),
                ObjectType(ObjectIdentity(OIDS["base"]["sysServices"])),
                ObjectType(ObjectIdentity(OIDS["interfaces"]["ifNumber"])) 
            )

            if not errorIndication and not errorStatus:
                return {
                    'transport': transport,
                    'sysName': str(varBinds[0][1]),
                    'sysDescr': str(varBinds[1][1]),
                    'sysServices': str(varBinds[2][1]),
                    'ifNumber': str(varBinds[3][1]) 
                }
        except Exception:
            pass
        return None

    def _identify_vendor(self, description):
        desc_lower = description.lower()
        for key, name in VENDOR_MAP.items():
            if key.lower() in desc_lower:
                return name
        return "Generic/Unknown"

    # --- POMOCNICZA FUNKCJA DO BEZPIECZNEGO ODPYTYWANIA POJEDYNCZYCH PACZEK PORTÓW ---
    async def _query_single_port(self, transport, community, port_idx):
        """Pobiera dane dla konkretnego indeksu portu przez ukierunkowany GET."""
        # UZUPEŁNIONO O LICZNIKI PAKIETÓW I BŁĘDÓW DLA IDS
        port_metrics_keys = [
            "ifDescr", "ifOperStatus", 
            "ifInOctets", "ifOutOctets", 
            "ifInUcastPkts", "ifOutUcastPkts",
            "ifInErrors", "ifOutErrors"
        ]
        query_objects = [ObjectType(ObjectIdentity(f"{OIDS['interfaces'][k]}.{port_idx}")) for k in port_metrics_keys]
        
        try:
            errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
                self.engine,
                CommunityData(community, mpModel=1),
                transport,
                ContextData(),
                *query_objects
            )
            if not errorIndication and not errorStatus:
                res_descr = varBinds[0][1].prettyPrint()
                if "No Such" in res_descr or not res_descr:
                    return None
                    
                return {
                    "port_idx": port_idx,
                    "data": {
                        "ifDescr": res_descr,
                        "ifOperStatus": varBinds[1][1].prettyPrint(),
                        "ifInOctets": varBinds[2][1].prettyPrint(),
                        "ifOutOctets": varBinds[3][1].prettyPrint(),
                        "ifInUcastPkts": varBinds[4][1].prettyPrint(),  
                        "ifOutUcastPkts": varBinds[5][1].prettyPrint(),
                        "ifInErrors": varBinds[6][1].prettyPrint(),
                        "ifOutErrors": varBinds[7][1].prettyPrint()
                    }
                }
        except Exception:
            pass
        return None

    async def get_device_metrics(self, device_data):
        """Pobiera wydajność oraz interfejsy switcha/routera bez używania blokującego WALK."""
        if not device_data or device_data.get('status') != 'up':
            return None

        ip = device_data['ip']
        vendor = device_data['vendor']
        if_count = device_data.get('ifNumber', 0) 
        
        if ip in self.auth_cache:
            transport = self.auth_cache[ip]['transport']
            community = self.auth_cache[ip]['community']
        else:
            community = device_data.get('community', 'public')
            try:
                transport = await UdpTransportTarget.create((ip, self.port), timeout=self.timeout, retries=self.retries)
                self.auth_cache[ip] = {'community': community, 'transport': transport}
            except Exception:
                return None

        results = {
            'ip': ip,
            'performance': {},
            'interfaces': []
        }

        # KROK 1: Pobieranie metryk systemowych (CPU/RAM)
        vendor_metrics = OIDS["performance"].get(vendor, {})
        if vendor_metrics:
            metric_names = list(vendor_metrics.keys())
            query_objects = [ObjectType(ObjectIdentity(oid)) for oid in vendor_metrics.values()]
            try:
                errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
                    self.engine, CommunityData(community, mpModel=1), transport, ContextData(), *query_objects
                )
                if not errorIndication and not errorStatus:
                    for i in range(len(varBinds)):
                        val = varBinds[i][1].prettyPrint()
                        if "No Such" not in val:
                            results['performance'][metric_names[i]] = val
                        else:
                            results['performance'][metric_names[i]] = None
            except Exception as e:
                print(f"[!] Błąd CPU/RAM dla {ip}: {e}")

        # Generujemy bazowe porty (1-24) dla klasycznych routerów
        target_indices = list(range(1, min(if_count, 24) + 1))
        
        # Jeśli to Cisco (np. Twój switch NM-16ESW), dorzucamy sztywne ID slotów modułu przełączającego
        if "cisco" in vendor.lower():
            # NM-16ESW mapuje porty fizyczne w slocie 1 jako indeksy od 101 do 116
            target_indices.extend(list(range(101, 117)))
            # Czasami VLANy managementowe lądują na wysokich indeksach (np. 5001 dla Vlan1)
            target_indices.append(5001)

        # Filtrujemy unikalne indeksy
        target_indices = sorted(list(set(target_indices)))

        # Odpytujemy o wszystkie potencjalne porty w tym samym czasie przez pętlę asyncio!
        port_tasks = [self._query_single_port(transport, community, idx) for idx in target_indices]
        port_results = await asyncio.gather(*port_tasks, return_exceptions=True)

        for port_res in port_results:
            # Ignorujemy błędy i puste odpowiedzi z nieaktywnych indeksów
            if not port_res or isinstance(port_res, Exception):
                continue
                
            p_idx = port_res["port_idx"]
            results['interfaces'].append({
                "if_number": p_idx,
                **port_res["data"]
            })

        return results