# My Simple Network Scanner

A lightweight Python-based ARP and SYN scanner designed to detect live hosts, scan common TCP ports, and attempt basic banner grabbing. Created for educational and cybersecurity research purposes.

## What It Does

This scanner performs three main tasks:

1. **ARP Scan:** Identifies live devices on a specified local network.
2. **SYN Scan:** Performs a TCP SYN scan on a list of common ports to identify open ports.
3. **Banner Grabbing:** Attempts to grab banners from services running on the open ports.
4. **OS Detection**: Estimates the operating system of a host based on TTL from TCP replies.

Example Output:
```nginx
[+] ARP scanning 192.168.1.0/24,,,
[+] Host found: 192.168.1.1 | d8:9e:f3:11:22:33
[+] SYN scanning 192.168.1.1...
[+] Results saved to results.json
```

## Project Structure
- scanner.py: Main scanner script 
- results.json: Scan output (auto-generated)
- README.md: This file

## Requirements:
- Python 3.7+
- Root/admin privileges (required for raw packet sending)
- The following Python libraries: scappy, socket, json, datetime

Install scapy if needed:
```bash
pip install scapy
```

## Usage:
```bash
sudo python3 scanner.py
```
When prompted, enter a network in CIDR format or a single IP:
```nginx
Enter network (e.g. 192.168.1.0/24 or single IP): 192.168.1.0/24
```
- ⚠️ The script limits scanning to /24 (max 256 hosts) to avoid long execution time. You can scan a single IP like 192.168.1.100 to focus on one device.

## Output:
Results are saved as a JSON file named results.json. It contains:
- IP and MAC addresses
- Open TCP ports
- Service banners (if available)
- Estimated OS (based on TTL)

Example JSON structure:
```json
{
  "network": "192.168.1.0/24",
  "scanned_at": "2025-06-02T13:00:00",
  "devices": [
    {
      "ip": "192.168.1.1",
      "mac": "d8:9e:f3:11:22:33",
      "os": "Linux/Unix",
      "open_ports": [22, 80],
      "banners": {
        "22": "SSH-2.0-OpenSSH_7.6",
        "80": "Apache HTTPD"
      }
    }
  ]
}
```
- If no banner is returned, the banner dictionary may be empty.

## Disclaimer:
This tool is for **educational** and **authorized** use only. **Do not scan networks or devices you do not own or have explicit permission to test.**
Unauthorized scanning is illegal and unethical.

## Learning Objectives:
- Understand ARP discovery and local subnet enumeration
- Explore TCP SYN scanning and port fingerprinting
- Practice basic banner grabbing with sockets
- Learn how TTL can be used for basic OS estimation
- Handle user interrupts and safely store partial scan results