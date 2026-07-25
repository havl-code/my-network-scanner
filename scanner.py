import os
import sys
import json
import socket
import signal
import logging
import argparse
from datetime import datetime
from ipaddress import ip_network, ip_address
from concurrent.futures import ThreadPoolExecutor, as_completed

# Suppress scapy's own noisy runtime warnings BEFORE importing it
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import ARP, Ether, srp, IP, TCP, UDP, ICMP, sr, sr1, conf, get_if_list

conf.verb = 0  # silence scapy's internal per-packet logging

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389]
DEFAULT_UDP_PORTS = [53, 67, 68, 69, 123, 161, 162, 500, 514, 1900]

results = {}    # global dictionary to hold scan results
QUIET = False   # set from CLI args in main()


def log(msg):
    if not QUIET:
        print(msg)


# function to handle keyboard interrupts and save results
def handle_interrupt(sig, frame):
    print("\n[!] Caught keyboard interrupt. Saving scan results...")
    if results.get("devices"):
        output = results.pop("_output", "results.json")
        save_results(results, output)
    else:
        print("[!] No results to save.")
    sys.exit(0)


signal.signal(signal.SIGINT, handle_interrupt)


def require_root():
    """Raw sockets need root/admin. Fail with a clear message instead of a raw traceback."""
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[!] This script needs root privileges (raw packet access). Try: sudo python3 scanner.py")
        sys.exit(1)


def parse_ports(spec):
    """Parse a ports spec like '22,80,100-110' into a sorted list of ints."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


# function to perform ARP scan on local network
def arp_scan(network, iface=None):
    log(f"[+] ARP scanning {network}...")

    devices = []
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    try:
        if "/" in network:
            hosts = list(ip_network(network, strict=False).hosts())
            if len(hosts) > 256:
                print(f"[!] Too many hosts ({len(hosts)}). Limit to a /24 or smaller.")
                return []
            targets = [str(ip) for ip in hosts]
        else:
            ip_address(network)
            targets = [network]
    except ValueError:
        print("[!] Invalid IP/network format.")
        return []

    try:
        pkt = ether / ARP(pdst=targets)
        kwargs = {"timeout": 2, "verbose": False}
        if iface:
            kwargs["iface"] = iface
        answered, _ = srp(pkt, **kwargs)
        for _, received in answered:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    except KeyboardInterrupt:
        print("\n[!] ARP scan interrupted.")
    except PermissionError:
        print("[!] Permission denied sending raw packets. Run with sudo.")
        sys.exit(1)
    return devices


# function to perform a batched TCP SYN scan on a list of ports
def syn_scan(ip, ports, timeout=1, retries=1):
    """
    Sends all SYN probes for a host in one batch (scapy's sr, not a per-port sr1 loop),
    which is much faster than probing ports one at a time since scapy fires them off
    together and collects replies as they come in, rather than waiting on a full
    round trip before sending the next probe. Ports that get no reply are retried
    up to `retries` times before being called closed.
    """
    log(f"[+] SYN scanning {ip}...")
    open_ports = []
    remaining = list(ports)

    try:
        for attempt in range(retries + 1):
            if not remaining:
                break

            pkts = [IP(dst=ip) / TCP(dport=p, flags="S") for p in remaining]
            answered, _unanswered = sr(pkts, timeout=timeout, verbose=False)

            for sent, resp in answered:
                port = sent[TCP].dport
                if resp.haslayer(TCP) and resp[TCP].flags == 0x12:  # SYN-ACK -> open
                    open_ports.append(port)
                    rst = IP(dst=ip) / TCP(dport=port, flags="R", seq=resp[TCP].ack)
                    sr1(rst, timeout=timeout, verbose=False)
                # any other real reply (e.g. RST-ACK) means closed - don't retry

            # only ports that got literally no reply are worth retrying
            answered_ports = {sent[TCP].dport for sent, _ in answered}
            remaining = [p for p in remaining if p not in answered_ports]
    except KeyboardInterrupt:
        print(f"\n[!] Interrupted SYN scan on {ip}.")

    return sorted(open_ports)


# function to perform a basic UDP scan
def udp_scan(ip, ports, timeout=1):
    """
    UDP has no handshake, so results here are inherently fuzzier than the TCP scan:
    a real UDP reply means the port is open, an ICMP port-unreachable means it's
    closed, and silence is reported as open|filtered since that's genuinely
    ambiguous over UDP (could be an open port that just didn't answer, or a
    firewall silently dropping the probe).
    """
    log(f"[+] UDP scanning {ip}...")
    open_or_filtered = []
    try:
        for port in ports:
            pkt = IP(dst=ip) / UDP(dport=port)
            resp = sr1(pkt, timeout=timeout, verbose=False)
            if resp is None:
                open_or_filtered.append(port)  # ambiguous, no reply at all
            elif resp.haslayer(ICMP) and resp[ICMP].type == 3 and resp[ICMP].code == 3:
                continue  # ICMP port-unreachable -> closed, drop it
            else:
                open_or_filtered.append(port)  # got a real UDP reply -> open
    except KeyboardInterrupt:
        print(f"\n[!] Interrupted UDP scan on {ip}.")
    return sorted(open_or_filtered)


# function to grab banner from a given port
def grab_banner(ip, port, timeout=1):
    try:
        with socket.socket() as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            banner = s.recv(1024).decode(errors="ignore")
        return banner.strip() or None
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def ttl_to_os(ttl):
    """Map a TCP reply TTL to a rough OS guess. Coarse heuristic, not real fingerprinting."""
    if ttl <= 64:
        return "Linux/Unix"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "Cisco/Networking Device"
    return "Unknown"


# function to estimate OS based on TTL value from TCP response
def detect_os(ip, fallback_ports=None, timeout=1):
    ports_to_try = fallback_ports or [80, 443, 22]
    for port in ports_to_try:
        try:
            pkt = IP(dst=ip) / TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=timeout, verbose=False)
            if resp:
                return ttl_to_os(resp.ttl)
        except (socket.timeout, OSError):
            continue
    return "Unknown"


# function to scan a single host end-to-end (ports, banners, OS) - used for threaded scanning
def scan_host(device, common_ports, timeout, retries, udp_ports=None):
    ip = device["ip"]
    mac = device["mac"]
    log(f"\n[+] Host found: {ip} | {mac}")

    ports = syn_scan(ip, common_ports, timeout=timeout, retries=retries)

    banners = {}
    for port in ports:
        banner = grab_banner(ip, port)
        if banner:
            banners[port] = banner

    os_type = detect_os(ip, ports)

    result = {
        "ip": ip,
        "mac": mac,
        "os": os_type,
        "open_ports": ports,
        "banners": banners,
    }

    if udp_ports:
        result["open_udp_ports"] = udp_scan(ip, udp_ports, timeout=timeout)

    return result


# function to save scan results to a JSON file
def save_results(data, filename="results.json"):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"[+] Results saved to {filename}")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Simple ARP + SYN network scanner.")
    parser.add_argument("network", nargs="?", help="CIDR network or single IP (prompted if omitted)")
    parser.add_argument("--ports", default=None, help="TCP ports, e.g. '22,80,1000-1010' (default: common ports list)")
    parser.add_argument("--udp", action="store_true", help="also run a UDP scan")
    parser.add_argument("--udp-ports", default=None, help="UDP ports to probe if --udp is set (default: common UDP ports)")
    parser.add_argument("--timeout", type=float, default=1.0, help="per-probe timeout in seconds")
    parser.add_argument("--retries", type=int, default=1, help="retries for TCP ports with no response")
    parser.add_argument("--iface", default=None, help="network interface to send/receive on")
    parser.add_argument("--list-ifaces", action="store_true", help="list available interfaces and exit")
    parser.add_argument("--output", default="results.json", help="output filename")
    parser.add_argument("--quiet", action="store_true", help="suppress progress output")
    return parser.parse_args(argv)


# main function that coordinates the entire scanning process
def main():
    global results, QUIET
    args = parse_args()
    QUIET = args.quiet

    if args.list_ifaces:
        for name in get_if_list():
            print(name)
        return

    require_root()

    network = args.network or input("Enter network (e.g. 192.168.1.0/24 or single IP): ").strip()
    tcp_ports = parse_ports(args.ports) if args.ports else COMMON_PORTS
    udp_ports = (parse_ports(args.udp_ports) if args.udp_ports else DEFAULT_UDP_PORTS) if args.udp else None

    results = {
        "network": network,
        "scanned_at": datetime.now().isoformat(),
        "devices": [],
        "_output": args.output,  # used by the interrupt handler, stripped before saving
    }

    devices = arp_scan(network, iface=args.iface)
    if not devices:
        print("[!] No devices found.")
        return

    max_workers = min(10, len(devices))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(scan_host, device, tcp_ports, args.timeout, args.retries, udp_ports)
            for device in devices
        ]
        for future in as_completed(futures):
            try:
                results["devices"].append(future.result())
            except Exception as e:
                print(f"[!] Error scanning host: {e}")

    results.pop("_output", None)

    if not results["devices"]:
        print("[!] No results to save.")
        return

    save_results(results, args.output)


if __name__ == "__main__":
    main()