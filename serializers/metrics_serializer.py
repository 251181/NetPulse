def serialize_metrics(grouped_metrics):
    devices = []

    for ip, metrics in grouped_metrics.items():
        devices.append(serialize_device(ip, metrics))

    return devices

def serialize_device(ip, metrics):
    cpu = []
    ram = []
    rx_bytes = []
    tx_bytes = []
    rx_packets = []
    tx_packets = []
    timestamps = []

    prev_rx = prev_tx = prev_rx_p = prev_tx_p = None

    for m in metrics:
        cpu.append(m.get("cpu"))
        ram.append(m.get("ram"))
        timestamps.append(m["timestamp"].isoformat())

        rx = m["rx_bytes"]
        tx = m["tx_bytes"]
        rx_p = m["rx_packets"]
        tx_p = m["tx_packets"]

        rx_bytes.append(0 if prev_rx is None else max(0, rx - prev_rx))
        tx_bytes.append(0 if prev_tx is None else max(0, tx - prev_tx))
        rx_packets.append(0 if prev_rx_p is None else max(0, rx_p - prev_rx_p))
        tx_packets.append(0 if prev_tx_p is None else max(0, tx_p - prev_tx_p))

        prev_rx, prev_tx, prev_rx_p, prev_tx_p = rx, tx, rx_p, tx_p

    return {
        "ip": ip,
        "cpu": cpu,
        "ram": ram,
        "rx_bytes": rx_bytes,
        "tx_bytes": tx_bytes,
        "rx_packets": rx_packets,
        "tx_packets": tx_packets,
        "timestamps": timestamps
    }
