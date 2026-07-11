from datetime import datetime, timezone, timedelta

DETECTION_WINDOW_SECONDS = 15


def serialize_devices(devices):
    return [serialize_device(d) for d in devices]


def serialize_device(device):
    last_seen = device.get("last_seen")

    if last_seen is not None:
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)

    detected = (
        last_seen is not None and
        (datetime.now(timezone.utc) - last_seen)
        < timedelta(seconds=DETECTION_WINDOW_SECONDS)
    )

    return {
        "id": str(device.get("_id")),
        "ip": device.get("ip"),
        "detected": detected,

        "general": serialize_general(device.get("general_info", {})),
        "interfaces": serialize_interfaces(device.get("interfaces", [])),
        "performance": serialize_performance(device.get("performance", {}))
    }


def serialize_general(info):
    return {
        "status": info.get("status"),
        "vendor": info.get("vendor"),
        "name": info.get("sysName"),
        "description": info.get("sysDescr"),
        "type": info.get("device_type")
    }


def serialize_interfaces(interfaces):
    return [
        {
            "name": i.get("ifDescr"),
            "status": "up" if i.get("ifOperStatus") == "1" else "down",

            "rx_bytes": int(i.get("ifInOctets", 0)),
            "tx_bytes": int(i.get("ifOutOctets", 0)),

            "rx_packets": int(i.get("ifInUcastPkts", 0)),
            "tx_packets": int(i.get("ifOutUcastPkts", 0)),

            "rx_errors": int(i.get("ifInErrors", 0)),
            "tx_errors": int(i.get("ifOutErrors", 0))
        }
        for i in interfaces
    ]


def serialize_performance(p):
    if not p:
        return {}

    normalized = {}

    try:
        if "cpu_idle" in p:
            normalized["cpu_percent"] = 100 - float(p.get("cpu_idle", 0))

        elif "cpu_1min" in p:
            normalized["cpu_percent"] = float(p.get("cpu_1min", 0))

        elif "cpu_load_1m" in p:
            normalized["cpu_percent"] = float(p.get("cpu_load_1m", 0)) * 100

    except:
        normalized["cpu_percent"] = None

    try:
        if "ram_total" in p:
            total = float(p.get("ram_total", 0))
            free = float(p.get("ram_free", 0))
            cached = float(p.get("ram_cached", 0))
            buffered = float(p.get("ram_buffered", 0))

            normalized["memory_used_bytes"] = max(
                0,
                total - free - cached - buffered
            )

        elif "mem_pool_processor_used" in p:
            normalized["memory_used_bytes"] = (
                float(p.get("mem_pool_processor_used", 0)) +
                float(p.get("mem_pool_io_used", 0))
            )

    except:
        normalized["memory_used_bytes"] = None

    return {
        "normalized": normalized,
        "raw": p
    }
