# import libraries
from scapy.all import ARP, Ether, srp, IP, TCP, sr1     # modules for crafting and sending packets
import socket                                           # for banner grabbing
import json                                             # for saving results to a file
from datetime import datetime                           # for timestamping the scan

# function to perform ARP scan on the local network
def arp_scan(network):
    print(f"[+] ARP scanning {network},,,")
    arp = ARP(pdst=network)                                 # create ARP request for the target network
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")                  # broadcast Ethernet frame
    packet = ether / arp                                    # combine Ethernet and ARP to make full packet
    result = srp(packet, timeout = 2, verbose = False)[0]   # send and receive

    devices = []    # list to store discovered devices
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})    # extract IP and MAC addresses
    return devices

# function to perform SYN scan on specific ports of a host
def syn_scan(ip, ports):
    print(f"[+] SYN scanning {ip}...")
    open_ports = []
    for port in ports:
        pkt = IP(dst=ip)/TCP(dport=port, flags = "S")               # craft SYN packet
        resp = sr1(pkt, timeout = 1, verbose = False)               # send packet and wait
        if resp and resp.haslayer(TCP) and resp[TCP].flags == 0x12: # SYN+ACK = open port
            open_ports.append(port)
    return open_ports

# function to grab banner from a given port (e.g., HTTP, FTP greetings)
def grab_banner(ip, port):
    try:
        s = socket.socket()                                     # create TCP socket
        s.settimeout(1)                                         # set timeout to avoid hanging
        s.connect((ip, port))                                   # connect to target port
        banner = s.recv(1024).devode(errors="ignore").script()  # receive and decode banner
        s.close()                                               # close socket
        return banner                                           
    except:
        return None                                             # return None if banner grabbing fails
    
# function to save scan results to a JSON file    
def save_results(data, filename = "results.json"):
    with open(filename, "w") as f:
        json.dump(data, f, indent = 4)  # dump data as formatted JSON
    print(f"[+] Results saved to {filename}")

# main function that coordinates the entire scanning process
def main():
    network = input("Enter network (e.g. 192.168.1.0/24): ").strip()    # get network input
    common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389]    # list of ports to scan

    results = {
        "network": network,
        "scanned_at": datetime.now().isoformat(),   # timestamp of scan
        "devices": []
    }

    devices = arp_scan(network) # run ARP scan
    for device in devices:
        ip = device["ip"]
        mac = device["mac"]
        print(f"\n[+] Host found: {ip} | {mac}")
        ports = syn_scan(ip, common_ports)      # scan for open ports
        banners = {}
        for port in ports:
            banner = grab_banner(ip, port)      # try grabbing banner
            if banner:
                banners = grab_banner(ip, port) # store banner by port
        results["devices"].append({
            "ip": ip,
            "mac": mac,
            "open_ports": ports,
            "banners": banners
        })

    save_results(results)   # save all results to file

# entry point: run main function unless script was imported
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan aborted by user.")