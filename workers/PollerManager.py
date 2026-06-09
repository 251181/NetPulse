import asyncio
import json
import aiofiles

from db_tools.db_tools import store_device

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
                devices_lookup_table.clear()  # Czyścimy istniejący słownik przed aktualizacją
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

        return monitored_devices

    async def poll_metrics(self, poller):
        if not monitored_devices:
            print("[!] Brak urządzeń do monitorowania.")
            return

        print("[*] Pobieranie metryk wydajnościowych dla monitorowanych urządzeń...")
        metric_tasks = [poller.get_device_metrics(data) for data in monitored_devices.values()]
        metrics_results = await asyncio.gather(*metric_tasks)

        for ip, result in zip(monitored_devices.keys(), metrics_results):
            if result:
                #print(f"  - Metryki dla {ip}:")
                #for metric_name, metric_value in result["performance"].items():
                #    print(f"    - {metric_name}: {metric_value}")

                store_device(ip=ip, performance=result.get("performance"), interfaces=result.get("interfaces"))
            else:
                print(f"  - Nie można pobrać metryk dla {ip}")
                # TODO dodanie urządzeń nieodpowiadajacych na snmp, ale istniejacych w sieci