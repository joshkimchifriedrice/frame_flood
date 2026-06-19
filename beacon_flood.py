#!/usr/bin/env python3
from scapy.all import *
import time
import random
import argparse

def create_beacon(ssid, bssid, channel=6, encryption=True):
    # Management frame: Beacon
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",  # Broadcast
                  addr2=bssid, addr3=bssid)
    
    beacon = Dot11Beacon(cap="ESS+privacy" if encryption else "ESS")
    
    # SSID element
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    
    # Supported rates (basic)
    rates = Dot11Elt(ID="Rates", info=b'\x82\x84\x8b\x96')
    
    # DS Parameter (channel)
    ds = Dot11Elt(ID="DSset", info=chr(channel).encode())
    
    # RSN (WPA2) if encrypted
    if encryption:
        rsn = Dot11Elt(ID="RSNinfo", info=(
            b'\x01\x00'  # Version
            b'\x00\x0f\xac\x04'  # Group cipher AES
            b'\x02\x00'
            b'\x00\x0f\xac\x04'  # Pairwise AES
            b'\x00\x0f\xac\x02'  # AKM PSK
            b'\x01\x00'
            b'\x00\x0f\xac\x02'  # More
            b'\x00\x00'
        ))
        frame = RadioTap()/dot11/beacon/essid/rates/ds/rsn
    else:
        frame = RadioTap()/dot11/beacon/essid/rates/ds
    
    return frame

def main():
    parser = argparse.ArgumentParser(description="Send multiple rogue AP beacons")
    parser.add_argument("-i", "--iface", default="wlan0mon", help="Monitor interface")
    parser.add_argument("-n", "--num", type=int, default=10, help="Number of fake APs")
    parser.add_argument("-c", "--channel", type=int, default=6, help="Channel")
    parser.add_argument("--interval", type=float, default=0.1, help="Beacon interval in seconds")
    parser.add_argument("--ssid-prefix", default="RogueAP_", help="SSID prefix")
    args = parser.parse_args()

    print(f"Sending beacons for {args.num} rogue APs on {args.iface} (channel {args.channel})")
    print("Press Ctrl+C to stop.")

    packets = []
    for i in range(args.num):
        ssid = f"{args.ssid_prefix}{i+1}"
        # Random but consistent BSSID for each AP
        bssid = RandMAC()  # Or use a fixed pattern like f"00:11:22:33:44:{i:02x}"
        pkt = create_beacon(ssid, bssid, args.channel)
        packets.append(pkt)
        print(f"  [+] {ssid} ({bssid})")

    try:
        while True:
            for pkt in packets:
                sendp(pkt, iface=args.iface, verbose=False)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped.")

if __name__ == "__main__":
    main()