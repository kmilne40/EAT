#!/usr/bin/env python3

import argparse
import re
import sys

try:
    # Standard Scapy
    from scapy.all import (
        sniff,
        wrpcap,
        TCP
    )
except ImportError:
    print("Scapy is not installed. Please install it via pip:  pip install scapy")
    sys.exit(1)

# For optional TLS parsing (scapy-ssl_tls):
# from scapy.layers.ssl_tls import TLS, TLSClientHello, TLSServerHello

def get_default_iface_name_linux():
    """
    Attempt to determine the default gateway interface on Linux.
    """
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines():
                try:
                    iface, dest, _, flags, _, _, _, _, _, _, _, = line.strip().split()
                    # Check for default route (dest == '00000000') and 'UP' & 'GATEWAY' flags
                    if dest != '00000000' or not int(flags, 16) & 2:
                        continue
                    return iface
                except:
                    continue
    except FileNotFoundError:
        pass
    return None

class Port(int):
    """
    A Network Port (i.e., 0 < integer <= 65535)
    """
    def __new__(cls, val, *args, **kwargs):
        new_int = int.__new__(cls, val, *args, **kwargs)
        if not 0 < new_int <= 65535:
            raise ValueError("Port out of range: %d" % new_int)
        return new_int

#
# EBCDIC/3270-specific pattern:
# If you truly have 3270 traffic, it may look for this pattern:
#
EBCDIC_REGEX = re.compile(b"\x7d..\x11..(.*)\x40*\xff\xef$")

def sniff_ascii(target, port, interface):
    """
    Capture ASCII traffic in real time from both directions (client->server, server->client).
    Print the payload as soon as it's seen, and write the packets to pcap.
    """
    filter_str = f"host {target} and port {port} and tcp"

    def ascii_callback(packet):
        if packet.haslayer(TCP):
            payload = bytes(packet[TCP].payload)
            if payload:
                # Attempt to decode as ASCII, replacing non-ASCII bytes
                text = payload.decode('ascii', errors='replace')
                # Print only if there's something
                if text.strip():
                    print(f"[ASCII] {text}")

    print(f"Starting ASCII capture on interface '{interface}' for {target}:{port}")
    print("Press Ctrl+C to stop...\n")

    packets = sniff(filter=filter_str, iface=interface, prn=ascii_callback)
    wrpcap("traffic.pcap", packets)
    print("Done! Packets saved to traffic.pcap.")

def sniff_ebcdic(target, port, interface):
    """
    Capture EBCDIC (3270-like) traffic in real time from both directions,
    looking for the specific 3270 user input pattern, and print the decoded text.
    """
    filter_str = f"host {target} and port {port} and tcp"

    def ebcdic_callback(packet):
        if packet.haslayer(TCP):
            payload = bytes(packet[TCP].payload)
            if not payload:
                return
            # Use the EBCDIC pattern
            match = re.search(EBCDIC_REGEX, payload)
            if match:
                try:
                    ebcdic_text = match.group(1).decode('cp500', errors='replace')
                    if ebcdic_text.strip():
                        print(f"[EBCDIC] {ebcdic_text}")
                except UnicodeDecodeError:
                    pass

    print(f"Starting EBCDIC capture on interface '{interface}' for {target}:{port}")
    print("Press Ctrl+C to stop...\n")

    packets = sniff(filter=filter_str, iface=interface, prn=ebcdic_callback)
    wrpcap("traffic.pcap", packets)
    print("Done! Packets saved to traffic.pcap.")

def sniff_tls(interface):
    """
    Sniffs TLS (port 443) traffic on the specified interface.
    By default, this only captures encrypted packets. If you want
    to parse or decrypt them, you'll need additional setup:
      1) scapy-ssl_tls (and import scapy.layers.ssl_tls)
      2) SSLKEYLOGFILE or a MITM approach to get session keys
    """

    filter_str = "tcp and port 443"

    def tls_packet_callback(packet):
        # With default scapy, you'll mostly see raw TCP with encrypted data.
        # If you have scapy-ssl_tls, you could parse handshake messages, etc.
        print("TLS packet captured (likely encrypted)")

    print(f"Starting TLS capture on interface='{interface}', port=443")
    print("Press Ctrl+C to stop...\n")

    packets = sniff(filter=filter_str, iface=interface, prn=tls_packet_callback)
    wrpcap("tls_traffic.pcap", packets)
    print("Done! TLS packets saved to tls_traffic.pcap.")

def main():
    parser = argparse.ArgumentParser(
        description="Packet Sniffer that supports ASCII, EBCDIC (3270), or TLS capture."
    )
    parser.add_argument("TARGET",
                        help="Target IP for traffic sniffing (omit if --tls is used).",
                        nargs="?",
                        default=None)
    parser.add_argument("-p", "--port",
                        help="Target port (Default: 3270)",
                        default=3270, type=Port)
    parser.add_argument("-i", "--iface",
                        help="Interface to use (default: tries system default).",
                        default=get_default_iface_name_linux())
    parser.add_argument("-e", "--encoding",
                        help="Choose 'ebcdic' or 'ascii' (Default: ebcdic) -- ignored if --tls is used.",
                        default="ebcdic", choices=["ebcdic", "ascii"])
    parser.add_argument("--tls", action="store_true",
                        help="Capture TLS traffic on port 443 instead of EBCDIC/ASCII. "
                             "If specified, TARGET and PORT are ignored.")
    args = parser.parse_args()

    if args.tls:
        # TLS capture
        if not args.iface:
            print("Could not determine default interface; please specify -i <interface>.")
            sys.exit(1)
        sniff_tls(args.iface)
    else:
        # EBCDIC or ASCII capture
        if not args.TARGET:
            print("Error: You must specify a TARGET unless you use --tls.")
            sys.exit(1)
        if not args.iface:
            print("Could not determine default interface; please specify -i <interface>.")
            sys.exit(1)

        if args.encoding.lower() == 'ascii':
            sniff_ascii(args.TARGET, args.port, args.iface)
        else:
            sniff_ebcdic(args.TARGET, args.port, args.iface)

if __name__ == "__main__":
    main()
