def serialize_hosts(hosts):
    hosts_info = []
    i = 1

    for h in hosts:
        hosts_info.append({"host_index": i, "ip": h["ip"]})
        i += 1

    return hosts_info
