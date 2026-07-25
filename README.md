# my-network-scanner

[![Tests](https://github.com/havl-code/my-network-scanner/actions/workflows/tests.yml/badge.svg)](https://github.com/havl-code/my-network-scanner/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/python-3.7%2B-blue)](https://www.python.org/)
[![Licence](https://img.shields.io/badge/licence-MIT-green)](LICENSE)

A lightweight Python ARP + SYN scanner that finds live hosts on a local network, checks TCP (and optionally UDP) ports, grabs service banners where it can, and takes a rough guess at each host's OS from its TTL. Built for learning how basic network reconnaissance tools work under the hood.

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
- **Batched SYN scanning via scapy.** All ports for a host are probed in a single batched send (`sr`) rather than one at a time, which is far faster than waiting a full timeout per port before sending the next. A RST is sent back after each open port is found so scanned hosts aren't left with half-open connections.
- **Retries on silence, not on a real reply.** A port that gives no response at all gets probed again (up to `--retries` times) since packet loss happens. A port that replies with something definite (like a RST) is trusted immediately and not re-probed.
- **UDP results are reported as open|filtered, not open.** UDP has no handshake: a real reply means open, an ICMP port-unreachable means closed, but silence is genuinely ambiguous (could be an open port that didn't answer, or a firewall dropping the probe), so it's labelled accordingly rather than guessed.
- **OS guessing is TTL-only, and it's a guess.** TTL ranges (`<=64` → Linux/Unix, `<=128` → Windows, `<=255` → networking gear) are a rough heuristic, not fingerprinting. Plenty of hosts won't match cleanly.
- **Concurrent host scanning.** Once live hosts are known, each one is scanned in its own thread (up to 10 at a time), so a subnet full of hosts doesn't scan one by one in sequence.
- **Capped at /24.** Anything larger than 256 hosts is rejected up front rather than allowed to run indefinitely; scan a single IP instead if you only care about one device.
- **Interrupt-safe.** Ctrl+C triggers a signal handler that saves whatever's been found so far instead of losing the whole scan.

## Requirements

- Python 3.7+
- Root/admin privileges, or a python binary granted raw-socket capability (see Known limitations)
- [`scapy`](https://pypi.org/project/scapy/), the only third-party runtime dependency; everything else (`socket`, `json`, `datetime`, `signal`, `ipaddress`, `argparse`) is Python standard library

## Setup

```bash
git clone https://github.com/havl-code/my-network-scanner.git
cd my-network-scanner
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

Raw packet access needs elevated privileges. Because `sudo` resets `PATH` to the system Python, running `sudo python scanner.py` from inside an activated venv will fail with `ModuleNotFoundError: No module named 'scapy'` even though it's installed, because sudo isn't seeing your venv. Use:

```bash
sudo .venv/bin/python scanner.py
```

Basic usage, same as before:

```bash
sudo .venv/bin/python scanner.py 192.168.1.0/24
```

Or omit the network argument to be prompted interactively:
```
Enter network (e.g. 192.168.1.0/24 or single IP): 192.168.1.0/24
```

### Options

| Flag | Default | Description |
|---|---|---|
| `network` | *(prompts if omitted)* | CIDR network or single IP |
| `--ports` | common ports list | TCP ports to scan, e.g. `22,80,1000-1010` |
| `--udp` | off | also run a UDP scan |
| `--udp-ports` | common UDP ports list | UDP ports to probe if `--udp` is set |
| `--timeout` | `1.0` | per-probe timeout in seconds |
| `--retries` | `1` | retries for TCP ports that get no response |
| `--iface` | scapy's default | network interface to send/receive on |
| `--list-ifaces` | | list available interfaces and exit |
| `--output` | `results.json` | output filename |
| `--quiet` | off | suppress progress output |

Examples:

```bash
# scan a single host on a custom port range, with more retries on a flaky network
sudo .venv/bin/python scanner.py 192.168.1.50 --ports 20-1024 --retries 2

# scan a subnet on a specific interface, including UDP
sudo .venv/bin/python scanner.py 192.168.1.0/24 --iface eth0 --udp

# see what interfaces scapy can see
sudo .venv/bin/python scanner.py --list-ifaces
```

## Output

Results are saved to `results.json` (or whatever `--output` was set to):

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
      "open_udp_ports": [53],
      "banners": {
        "22": "SSH-2.0-OpenSSH_7.6",
        "80": "Apache HTTPD"
      }
    }
  ]
}
```

`open_udp_ports` only appears when `--udp` was used. If a host has no reachable banner on any open port, its `banners` object is simply empty.

## Testing

Core logic that doesn't need root or a live network (port-spec parsing, TTL-to-OS mapping, CLI argument parsing, and network-input validation) has unit tests under `tests/`, run automatically on every push via GitHub Actions (see the Tests badge above).

```bash
pip install -r requirements-dev.txt
pytest -v
```

The raw-socket parts (`arp_scan` sending packets, `syn_scan`, `udp_scan`) aren't covered by automated tests since they genuinely need root and a live network to exercise; they're better verified by actually running the scanner against a host you control.

## Known limitations

- **`sudo` + venv don't mix by default.** See the note under Usage: `sudo` uses the system python, not your venv's, unless you point it there explicitly.
- **`setcap` is an alternative to repeated `sudo`, but grants raw-socket power indefinitely** to whichever python binary you apply it to, and on most venvs that binary is actually your system-wide python. Only do this to a python you trust and control, and be aware of the scope before using it.
- **TTL-based OS detection is approximate.** It's a cheap heuristic, not real fingerprinting, and can misidentify hosts behind certain firewalls/NATs.
- **UDP results are inherently fuzzy.** `open|filtered` isn't a bug, it's a real limitation of scanning UDP without a handshake.
- **Capped at 256 hosts (/24).** Scan a single IP for anything larger, or run it multiple times across smaller ranges.

## Learning objectives

- ARP discovery and local subnet enumeration
- TCP SYN scanning and port fingerprinting, including batched sends for speed
- Basic UDP scanning and why its results are inherently less certain than TCP's
- Basic banner grabbing with raw sockets
- Using TTL for coarse OS estimation
- Handling interrupts and safely persisting partial results
- Concurrent scanning with a thread pool
- Writing a CLI with `argparse`
- Unit testing the parts of a networking tool that don't require root or a live network

## Disclaimer

For **educational** and **authorised** use only. Do not scan networks or devices you don't own or don't have explicit permission to test. Unauthorised scanning is illegal and unethical.

## Licence

Released under the MIT Licence, see [LICENSE](LICENSE).