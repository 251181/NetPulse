import asyncio
import json
import aiofiles

from db_tools.db_tools import store_device, build_metrics, store_metrics
from core.event_bus import push_event

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
                print(f"[*] Successfully loaded {len(data)} device mapping rules.")

        except FileNotFoundError:
            print(f"[!] Error: File {path} does not exist. Mapping dictionary is empty!")

        except json.JSONDecodeError:
            print(f"[!] Error: File {path} is not a valid JSON file!")


    async def poll_devices(self, poller, raw_hosts):
        discovery_tasks = [poller.get_device_identity(host['ip']) for host in raw_hosts]
        discovered_data = await asyncio.gather(*discovery_tasks)
        
        for data in discovered_data:
            if data['status'] == 'up':
                data.update({'device_type': resolve_device_type(data['sysDescr'])})

                monitored_devices[data['ip']] = data
                print(f"[+] Added to monitoring: {data['ip']} [{data['vendor']}]")
                store_device(ip=data["ip"], general_info=data)
            else:
                print(f"[-] Device {data['ip']} is unavailable (status: {data['status']})")
                store_device(ip=data["ip"], general_info={"status": data['status']})

        return monitored_devices

    async def poll_metrics(self, poller, snmp_analyzer=None):
        if not monitored_devices:
            print("[!] No devices to monitor.")
            return

        print("[*] Fetching performance metrics for monitored devices...")
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
                # DEBUGGING: Displaying fetched data in a structured format
                print(f"\n=== ALL DATA FOR DEVICE: {ip} ===")
                device_info = monitored_devices.get(ip, {})
                print(f"[BASE INFO] Name: {device_info.get('sysName')}, Vendor: {device_info.get('vendor')}, Type: {device_info.get('device_type')}")

                print(f"[PERFORMANCE]: {result.get('performance')}")

                print(f"[INTERFACES] (Number of collected: {len(result.get('interfaces', []))}):")
                for iface in result.get("interfaces", []):
                    # Wyciągamy opisy i statusy
                    if_num = iface.get('if_number')
                    if_descr = iface.get('ifDescr', 'Unknown')
                    status = iface.get('ifOperStatus', 'Unknown')
                    
                    in_bytes = iface.get('ifInOctets', '0')
                    out_bytes = iface.get('ifOutOctets', '0')
                    in_pkts = iface.get('ifInUcastPkts', '0')
                    out_pkts = iface.get('ifOutUcastPkts', '0')
                    in_errs = iface.get('ifInErrors', '0')
                    out_errs = iface.get('ifOutErrors', '0')
                    
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
                print(f"  - Cannot fetch metrics for {ip}") # TODO add to database as hosts with IP only
                
        push_event({'type': 'DATA_REFRESH_SIGNAL'})
        
        if analysis_tasks:
            await asyncio.gather(*analysis_tasks, return_exceptions=True)
        
        print("[*] Finished fetching performance metrics")