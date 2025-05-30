# My Simple Network Scanner

A lightweight Python-based ARP and SYN scanner designed to detect live hosts, scan common TCP ports, and attempt basic banner grabbing. Created for educational and cybersecurity research purposes.

## What It Does

This scanner performs three main tasks:

1. **ARP Scan:** Identifies live devices on a specified local network.
2. **SYN Scan:** Performs a TCP SYN scan on a list of common ports to identify open ports.
3. **Banner Grabbing:** Attempts to grab banners from services running on the open ports.

Example Output:
```nginx
[+] ARP scanning 192.168.1.0/24,,,
[+] Host found: 192.168.1.1 | d8:9e:f3:11:22:33
[+] SYN scanning 192.168.1.1...
[+] Results saved to results.json
```

## Project Structure
- scanner.py: Main script 
- results.json: Scan output (generated)
- README.md: You're here

## Requirements:
- Python 3.7+
- Root/admin privileges (for raw socket operations)
- The following Python libraries: scappy, socket, json, datetime

## Usage:
```bash
sudo python3 scanner.py
```
Enter the target network in CIDR notation when prompted:
```nginx
Enter network (e.g. 192.168.1.0/24):
```

## Output:
Results are saves as a JSON file (results.json) containing information such as:
- IP and MAC addresses
- Open TCP ports
- Banner data (if any)

Example JSON structure:
```json
{
  "network": "192.168.1.0/24",
  "scanned_at": "2025-05-30T13:00:00",
  "devices": [
    {
      "ip": "192.168.1.1",
      "mac": "d8:9e:f3:11:22:33",
      "open_ports": [80, 443],
      "banners": {
        "80": "Apache HTTPD",
        "443": "OpenSSL/1.1.1"
      }
    }
  ]
}
```

## Disclaimer:
This tool is for **educational** and **authorized** use only. Scanning networks you do not own or have permission to test is illegal and unethical.

## Learning Objectives:
- Learn how ARP and TCP work in practice
- Explore raw packet crafting with scapy
- Practice banner grabbing and basic network enumeration
- Understand how port scanning relates to cybersecurity auditing