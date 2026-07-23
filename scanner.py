import os
import sys
import json
import socket
import signal
import logging
from datetime import datetime
from ipaddress import ip_network, ip_address
from concurrent.futures import ThreadPoolExecutor, as_completed

# Suppress scapy's own noisy runtime warnings BEFORE importing it
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import ARP, Ether, srp, IP, TCP, sr1, conf

conf.verb = 0  # silence scapy's internal per-packet logging

results = {}    # global dictionary to hold scan results


# function to handle keyboard interrupts and save results
def handle_interrupt(sig, frame):
    print("\n[!] Caught keyboard interrupt. Saving scan results...")
    if results.get("devices"):
        save_results(results)           # save if there's something scanned
    else:
        print("[!] No results to save.")
    sys.exit(0)                         # exit the script gracefully


signal.signal(signal.SIGINT, handle_interrupt)  # register the signal handler for keyboard interrupts


def require_root():
    """Raw sockets need root/admin. Fail with a clear message instead of a raw traceback."""
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[!] This script needs root privileges (raw packet access). Try: sudo python3 scanner.py")
        sys.exit(1)


# function to perform ARP scan on local network
def arp_scan(network):
    print(f"[+] ARP scanning {network}...")

    devices = []        # list to store discovered devices
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # create Ethernet broadcast frame

    try:
        if "/" in network:
            hosts = list(ip_network(network, strict=False).hosts())  # parse all hosts in a subnet
            if len(hosts) > 256:
                print(f"[!] Too many hosts ({len(hosts)}). Limit to a /24 or smaller.")
                return []
            targets = [str(ip) for ip in hosts]  # convert to list of strings
        else:
            ip_address(network)  # validate single IP address
            targets = [network]  # single target mode
    except ValueError:
        print("[!] Invalid IP/network format.")
        return []

    try:
        pkt = ether / ARP(pdst=targets)  # create ARP request packet
        answered, _ = srp(pkt, timeout=2, verbose=False)  # send and receive packets
        for _, received in answered:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})  # collect IP and MAC
    except KeyboardInterrupt:
        print("\n[!] ARP scan interrupted.")  # catch Ctrl+C during scan
    except PermissionError:
        print("[!] Permission denied sending raw packets. Run with sudo.")
        sys.exit(1)
    return devices


# function to perform SYN scan on specific ports of a host
def syn_scan(ip, ports, timeout=1):
    print(f"[+] SYN scanning {ip}...")
    open_ports = []
    try:
        for port in ports:
            pkt = IP(dst=ip) / TCP(dport=port, flags="S")  # craft TCP SYN packet
            resp = sr1(pkt, timeout=timeout, verbose=False)  # send and wait for response
            if resp and resp.haslayer(TCP) and resp[TCP].flags == 0x12:
                open_ports.append(port)  # store open port
                # send RST to politely tear down the half-open connection
                rst = IP(dst=ip) / TCP(dport=port, flags="R", seq=resp[TCP].ack)
                sr1(rst, timeout=timeout, verbose=False)
    except KeyboardInterrupt:
        print(f"\n[!] Interrupted SYN scan on {ip}.")
    return open_ports


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


# function to estimate OS based on TTL value from TCP response
def detect_os(ip, fallback_ports=None, timeout=1):
    ports_to_try = fallback_ports or [80, 443, 22]  # use fallback ports if none open
    for port in ports_to_try:
        try:
            pkt = IP(dst=ip) / TCP(dport=port, flags="S")  # send SYN to the port
            resp = sr1(pkt, timeout=timeout, verbose=False)  # wait for response
            if resp:
                ttl = resp.ttl  # read TTL value from response
                if ttl <= 64:
                    return "Linux/Unix"
                elif ttl <= 128:
                    return "Windows"
                elif ttl <= 255:
                    return "Cisco/Networking Device"
                else:
                    return "Unknown"
        except (socket.timeout, OSError):
            continue  # try next port
    return "Unknown"  # no response from any probe port


# function to scan a single host end-to-end (ports, banners, OS) - used for threaded scanning
def scan_host(device, common_ports):
    ip = device["ip"]
    mac = device["mac"]
    print(f"\n[+] Host found: {ip} | {mac}")

    ports = syn_scan(ip, common_ports)  # scan for open ports on each host

    banners = {}
    for port in ports:
        banner = grab_banner(ip, port)   # call once, reuse the result
        if banner:
            banners[port] = banner

    os_type = detect_os(ip, ports)  # try OS fingerprinting

    return {
        "ip": ip,
        "mac": mac,
        "os": os_type,
        "open_ports": ports,
        "banners": banners,
    }


# function to save scan results to a JSON file
def save_results(data, filename="results.json"):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)  # save as pretty JSON
    print(f"[+] Results saved to {filename}")


# main function that coordinates the entire scanning process
def main():
    global results
    require_root()

    network = input("Enter network (e.g. 192.168.1.0/24 or single IP): ").strip()  # get user input
    common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389]  # list of ports to scan

    results = {
        "network": network,
        "scanned_at": datetime.now().isoformat(),  # store timestamp
        "devices": []
    }

    devices = arp_scan(network)  # run ARP scan to find live hosts
    if not devices:
        print("[!] No devices found.")
        return

    # scan hosts concurrently instead of one-by-one - big speedup on larger subnets
    max_workers = min(10, len(devices))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(scan_host, device, common_ports) for device in devices]
        for future in as_completed(futures):
            try:
                results["devices"].append(future.result())
            except Exception as e:
                print(f"[!] Error scanning host: {e}")

    if not results["devices"]:
        print("[!] No results to save.")
        return

    save_results(results)  # save everything to JSON file


# entry point: run main function unless script was imported
if __name__ == "__main__":
    main()