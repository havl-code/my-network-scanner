# my-network-scanner

[![Python](https://img.shields.io/badge/python-3.7%2B-blue)](https://www.python.org/)
[![Licence](https://img.shields.io/badge/licence-MIT-green)](LICENSE)

A lightweight Python ARP + SYN scanner that finds live hosts on a local network, checks a list of common TCP ports, grabs service banners where it can, and takes a rough guess at each host's OS from its TTL. Built for learning how basic network reconnaissance tools work under the hood.

```
[+] ARP scanning 192.168.1.0/24...
[+] Host found: 192.168.1.1 | d8:9e:f3:11:22:33
[+] SYN scanning 192.168.1.1...
[+] Results saved to results.json
```

## Why

Tools like `nmap` do all of this and far more, but using them doesn't teach you much about *how*. This project is the opposite: a small, readable script that does one scan of one subnet, so each piece (ARP discovery, SYN scanning, banner grabbing, TTL-based OS guessing) stays easy to read end to end.

## Design decisions

- **ARP first, then TCP.** A quick ARP sweep finds which hosts on the subnet are actually alive, so time isn't wasted port-scanning addresses nobody's using.
- **Raw SYN scanning via scapy.** Ports are probed with hand-crafted SYN packets rather than full TCP connections, and a RST is sent back after each open port is found so scanned hosts aren't left with half-open connections.
- **Banner grabbing is a single best-effort connection per port.** If a service doesn't respond within the timeout, it's just recorded as having no banner rather than retried, to keep the scan predictable in length.
- **OS guessing is TTL-only, and it's a guess.** TTL ranges (`<=64` → Linux/Unix, `<=128` → Windows, `<=255` → networking gear) are a rough heuristic, not fingerprinting. Plenty of hosts won't match cleanly.
- **Concurrent host scanning.** Once live hosts are known, each one is scanned in its own thread (up to 10 at a time), so a subnet full of hosts doesn't scan one-by-one in sequence.
- **Capped at /24.** Anything larger than 256 hosts is rejected up front rather than allowed to run indefinitely; scan a single IP instead if you only care about one device.
- **Interrupt-safe.** Ctrl+C triggers a signal handler that saves whatever's been found so far to `results.json` instead of losing the whole scan.

## Requirements

- Python 3.7+
- Root/admin privileges, or a python binary granted raw-socket capability (see Known limitations)
- [`scapy`](https://pypi.org/project/scapy/), the only third-party dependency; everything else (`socket`, `json`, `datetime`, `signal`, `ipaddress`) is Python standard library

## Setup

```bash
git clone https://github.com/havl-code/my-network-scanner.git
cd my-network-scanner
python -m venv .venv
source .venv/bin/activate
pip install scapy
```

## Usage

Raw packet access needs elevated privileges. Because `sudo` resets `PATH` to the system Python, running `sudo python scanner.py` from inside an activated venv will fail with `ModuleNotFoundError: No module named 'scapy'` even though it's installed, because sudo isn't seeing your venv. Use one of:

```bash
# point sudo at the venv's python directly
sudo .venv/bin/python scanner.py

# OR, run as your normal user with no sudo at all (one-time setup):
sudo setcap cap_net_raw,cap_net_admin=eip .venv/bin/python3
python scanner.py
```

You'll be prompted for a network:
```
Enter network (e.g. 192.168.1.0/24 or single IP): 192.168.1.0/24
```

## Output

Results are saved to `results.json`:

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

If a host has no reachable banner on any open port, its `banners` object is simply empty.

## Known limitations

- **`sudo` + venv don't mix by default.** See the note under Usage: `sudo` uses the system python, not your venv's, unless you point it there explicitly.
- **`setcap` grants raw-socket power indefinitely** to whichever python binary you apply it to. It's convenient, but only do this to a python you trust and control (e.g. your project's venv interpreter), not your system-wide python.
- **TTL-based OS detection is approximate.** It's a cheap heuristic, not real fingerprinting, and can misidentify hosts behind certain firewalls/NATs.
- **Capped at 256 hosts (/24).** Scan a single IP for anything larger, or run it multiple times across smaller ranges.
- **No retry logic on dropped packets.** A single missed SYN/ACK on a flaky network reads as a closed port; there's no re-probe.

## Learning objectives

- ARP discovery and local subnet enumeration
- TCP SYN scanning and port fingerprinting
- Basic banner grabbing with raw sockets
- Using TTL for coarse OS estimation
- Handling interrupts and safely persisting partial results
- Concurrent scanning with a thread pool

## Disclaimer

For **educational** and **authorised** use only. Do not scan networks or devices you don't own or don't have explicit permission to test. Unauthorised scanning is illegal and unethical.

## Licence

Released under the MIT Licence, see [LICENSE](LICENSE).