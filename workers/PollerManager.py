import asyncio
import json
import aiofiles

monitored_devices = {}

devices_lookup_table = {}

def resolve_device_type(sys_descr):
    for key in devices_lookup_table:
        if sys_descr.startswith(key):
            return devices_lookup_table[key]
    return "Unknown"


class PollerManager:
    async def load_lookup_table(self, path):
        """Asynchroniczne wczytywanie pliku JSON do słownika."""
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
                # zapis do bazy danych
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

        for ip, metrics in zip(monitored_devices.keys(), metrics_results):
            if metrics:
                print(f"  - Metryki dla {ip}:")
                for metric_name, metric_value in metrics.items():
                    print(f"    - {metric_name}: {metric_value}")
                    # zapis do bazy danych
            else:
                print(f"  - Nie można pobrać metryk dla {ip}")