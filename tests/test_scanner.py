import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scanner


# --- parse_ports ---

def test_parse_ports_single_values():
    assert scanner.parse_ports("22,80,443") == [22, 80, 443]


def test_parse_ports_range():
    assert scanner.parse_ports("20-23") == [20, 21, 22, 23]


def test_parse_ports_mixed_and_dedup():
    assert scanner.parse_ports("22,20-23,80,22") == [20, 21, 22, 23, 80]


def test_parse_ports_ignores_blank_segments():
    assert scanner.parse_ports("22,,80,") == [22, 80]


# --- ttl_to_os ---

def test_ttl_to_os_linux_boundary():
    assert scanner.ttl_to_os(1) == "Linux/Unix"
    assert scanner.ttl_to_os(64) == "Linux/Unix"


def test_ttl_to_os_windows_boundary():
    assert scanner.ttl_to_os(65) == "Windows"
    assert scanner.ttl_to_os(128) == "Windows"


def test_ttl_to_os_networking_device_boundary():
    assert scanner.ttl_to_os(129) == "Cisco/Networking Device"
    assert scanner.ttl_to_os(255) == "Cisco/Networking Device"


def test_ttl_to_os_unknown_above_255():
    assert scanner.ttl_to_os(300) == "Unknown"


# --- parse_args ---

def test_parse_args_defaults():
    args = scanner.parse_args(["192.168.1.0/24"])
    assert args.network == "192.168.1.0/24"
    assert args.ports is None
    assert args.udp is False
    assert args.udp_ports is None
    assert args.timeout == 1.0
    assert args.retries == 1
    assert args.iface is None
    assert args.output == "results.json"
    assert args.quiet is False


def test_parse_args_custom_flags():
    args = scanner.parse_args([
        "10.0.0.5",
        "--ports", "22,80",
        "--udp", "--udp-ports", "53,123",
        "--timeout", "2.5",
        "--retries", "3",
        "--iface", "eth0",
        "--output", "out.json",
        "--quiet",
    ])
    assert args.network == "10.0.0.5"
    assert args.ports == "22,80"
    assert args.udp is True
    assert args.udp_ports == "53,123"
    assert args.timeout == 2.5
    assert args.retries == 3
    assert args.iface == "eth0"
    assert args.output == "out.json"
    assert args.quiet is True


def test_parse_args_network_optional():
    args = scanner.parse_args([])
    assert args.network is None


# --- arp_scan input validation (no network/root needed, fails before any packet is sent) ---

def test_arp_scan_rejects_invalid_network(capsys):
    assert scanner.arp_scan("not-an-ip-or-cidr") == []
    assert "Invalid IP/network format" in capsys.readouterr().out


def test_arp_scan_rejects_oversized_network(capsys):
    assert scanner.arp_scan("10.0.0.0/8") == []
    assert "Too many hosts" in capsys.readouterr().out