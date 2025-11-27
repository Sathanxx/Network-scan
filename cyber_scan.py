#!/usr/bin/env python3

import os
import csv
import socket
from scapy.all import ARP, Ether, srp
import subprocess

def clear():
    os.system("clear")

def arp_scan(ip_range):
    print(f"\n[+] Scanning ARP Network {ip_range}")
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append([received.psrc, received.hwsrc])

    print("\nConnected Devices:")
    print("------------------------------")
    for ip, mac in devices:
        print(f"IP: {ip} \t MAC: {mac}")

    export_option(devices, ["IP", "MAC"])
    input("\nPress Enter to return to menu...")

def ping_sweep(ip_base):
    print("\n[+] Starting Ping Sweep...")
    devices = []

    for i in range(1, 255):
        ip = f"{ip_base}.{i}"
        response = os.system(f"ping -c 1 -W 1 {ip} > /dev/null 2>&1")
        if response == 0:
            print(f"[ACTIVE] {ip}")
            devices.append([ip])

    export_option(devices, ["IP"])
    input("\nPress Enter to return to menu...")

def port_scan(target):
    print(f"\n[+] Scanning top ports on {target}")
    ports = [21, 22, 23, 80, 443, 3306, 8080]
    results = []

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)

        try:
            sock.connect((target, port))
            results.append([port, "OPEN"])
            print(f"[OPEN] Port {port}")
        except:
            pass
        finally:
            sock.close()

    export_option(results, ["Port", "Status"])
    input("\nPress Enter to return to menu...")

def export_option(data, headers):
    if len(data) == 0:
        print("\nNo data to export.")
        return

    choice = input("\nDo you want to export results to CSV? (y/n): ").lower()
    if choice == "y":
        filename = input("Enter filename (example: output.csv): ")
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(data)
        print(f"[+] Saved as {filename}")

def menu():
    while True:
        clear()
        print("""============================================
     CYBER NETWORK SCANNER - BY JAFNA
============================================

[1] ARP Scan (Find Connected Devices)
[2] Ping Sweep (Find Active Hosts)
[3] Basic Port Scan
[4] Exit

============================================
""")

        choice = input("Select an option: ")

        if choice == "1":
            ip_range = input("Enter IP Range (example 192.168.1.0/24): ")
            arp_scan(ip_range)

        elif choice == "2":
            base = input("Enter base IP (example 192.168.1): ")
            ping_sweep(base)

        elif choice == "3":
            target = input("Enter target IP: ")
            port_scan(target)

        elif choice == "4":
            print("Exiting... Goodbye!")
            break

        else:
            print("Invalid option!")
            input("Press Enter...")

if __name__ == "__main__":
    menu()
