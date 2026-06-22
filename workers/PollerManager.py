import asyncio
import json
import aiofiles

from db_tools.db_tools import store_device, build_metrics, store_metrics, db

monitored_devices = {}

devices_lookup_table = {}

def resolve_device_type(sys_descr):
    sys_descr = sys_descr.lower()
    for key, value in devices_lookup_table.items():
        if key.lower() in sys_descr:
            return value

    return "Unknown"


class PollerManager:
    async def load_lookup_table(self, path):
        global devices_lookup_table
        try:
            async with aiofiles.open(path, mode='r', encoding='utf-8') as f:
                content = await f.read()
                data = json.loads(content)
                devices_lookup_table.clear()
                devices_lookup_table.update(data)
                print(f"[*] Pomyślnie wczytano {len(data)} reguł mapowania urządzeń.")

        except FileNotFoundError:
            print(f"[!] Błąd: Plik {path} nie istnieje. Słownik mapowania jest pusty!")

        except json.JSONDecodeError:
            print(f"[!] Błąd: Plik {path} nie jest poprawnym plikiem JSON!")


    async def poll_devices(self, poller, raw_hosts):
        discovery_tasks = [poller.get_device_identity(host['ip']) for host in raw_hosts]
        discovered_data = await asyncio.gather(*discovery_tasks)
        
        for data in discovered_data:
            if data['status'] == 'up':
                data.update({'device_type': resolve_device_type(data['sysDescr'])})

                monitored_devices[data['ip']] = data
                print(f"[+] Dodano do monitoringu: {data['ip']} [{data['vendor']}]")
                store_device(ip=data["ip"], general_info=data)
            else:
                print(f"[-] Urządzenie {data['ip']} jest niedostępne (status: {data['status']})")
                store_device(ip=data["ip"], general_info={"status": data['status']})

        return monitored_devices

    async def poll_metrics(self, poller, snmp_analyzer=None):
        if not monitored_devices:
            print("[!] Brak urządzeń do monitorowania.")
            return

        print("[*] Pobieranie metryk wydajnościowych dla monitorowanych urządzeń...")
        metric_tasks = [poller.get_device_metrics(data) for data in monitored_devices.values()]
        metrics_results = await asyncio.gather(*metric_tasks)

        analysis_tasks = []

        for ip, result in zip(monitored_devices.keys(), metrics_results):
            if result:
                store_device(ip=ip, performance=result.get("performance"), interfaces=result.get("interfaces"))

                metrics = build_metrics(
                    ip=ip,
                    performance=result.get("performance"),
                    interfaces=result.get("interfaces")
                )

                store_metrics(metrics)
                '''
                print(f"\n=== WSZYSTKIE DANE DLA URZĄDZENIA: {ip} ===")
                # Pobieramy statyczne dane "base", które wykryliśmy podczas Discovery
                device_info = monitored_devices.get(ip, {})
                print(f"[BASE INFO] Nazwa: {device_info.get('sysName')}, Vendor: {device_info.get('vendor')}, Typ: {device_info.get('device_type')}")

                # Wypisujemy dynamiczne metryki z obiektu result (CPU/RAM/System)
                print(f"[PERFORMANCE]: {result.get('performance')}")

                # Wypisujemy interfejsy wraz z pełnymi statystykami IDS (Pakiety, Błędy, Wolumetryka)
                print(f"[INTERFACES] (Liczba zebranych: {len(result.get('interfaces', []))}):")
                for iface in result.get("interfaces", []):
                    # Wyciągamy opisy i statusy
                    if_num = iface.get('if_number')
                    if_descr = iface.get('ifDescr', 'Unknown')
                    status = iface.get('ifOperStatus', 'Unknown')
                    
                    # Wyciągamy liczniki wolumetryczne i pakietowe pod IDS
                    in_bytes = iface.get('ifInOctets', '0')
                    out_bytes = iface.get('ifOutOctets', '0')
                    in_pkts = iface.get('ifInUcastPkts', '0')
                    out_pkts = iface.get('ifOutUcastPkts', '0')
                    in_errs = iface.get('ifInErrors', '0')
                    out_errs = iface.get('ifOutErrors', '0')
                    
                    # Formatujemy wyjście w jedną, czytelną linię per port
                    print(
                        f"    - Port {if_num} ({if_descr}) -> Status: {status} | "
                        f"Rx: {in_bytes}B ({in_pkts} pkts), Errors: {in_errs} | "
                        f"Tx: {out_bytes}B ({out_pkts} pkts), Errors: {out_errs}"
                    )
                    '''
                if snmp_analyzer:
                    task = asyncio.create_task(snmp_analyzer.analyze_metrics(result))
                    analysis_tasks.append(task)
            else:
                print(f"  - Nie można pobrać metryk dla {ip}") # TODO dodanie do bazy jako hosty z samym IP

        if analysis_tasks:
            await asyncio.gather(*analysis_tasks, return_exceptions=True)
        
        print("[*] Koniec pobierania metryk wydajnościowych")