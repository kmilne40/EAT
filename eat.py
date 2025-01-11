#!/usr/bin/env python3
import argparse
import json
import re
import sys

try:
    from scapy.all import (
        sniff,
        wrpcap,
        TCP,
        IP
    )
except ImportError:
    print("Scapy is not installed. Please install it via pip:  pip install scapy")
    sys.exit(1)

# For optional TLS parsing (if using scapy-ssl_tls):
# from scapy.layers.ssl_tls import TLS, TLSClientHello, TLSServerHello

###############################################################################
# Utility Functions
###############################################################################

def get_default_iface_name_linux():
    """
    Attempt to determine the default gateway interface on Linux by reading /proc/net/route.
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


###############################################################################
# Global Variables/Patterns
###############################################################################

# EBCDIC/3270-specific pattern:
# If you truly have 3270 traffic, this pattern might help detect user input.
EBCDIC_REGEX = re.compile(b"\x7d..\x11..(.*)\x40*\xff\xef$")

# ANSI escape codes for coloring output in the terminal
RED = "\033[91m"
RESET = "\033[0m"


###############################################################################
# Malicious IP Loading
###############################################################################

def load_malicious_ips(malicious_ip_file):
    """
    Load malicious IPs from a JSON file with a structure like:
      {
        "malicious_ips": [
          "192.168.1.10",
          "10.0.0.7"
        ]
      }
    Returns a set of IP strings considered malicious.
    """
    if not malicious_ip_file:
        return set()
    try:
        with open(malicious_ip_file, "r") as f:
            data = json.load(f)
            return set(data.get("malicious_ips", []))
    except Exception as e:
        print(f"Error loading malicious IP file: {e}")
        return set()


###############################################################################
# Sniffer Callbacks
###############################################################################

def parse_ascii(payload):
    """
    Attempt to decode payload as ASCII, replacing non-ASCII bytes. 
    Returns the decoded string or None if blank after stripping.
    """
    text = payload.decode('ascii', errors='replace')
    if text.strip():
        return text
    return None


def parse_ebcdic(payload):
    """
    Attempt to match and decode 3270-like EBCDIC data from the payload.
    Returns the decoded string or None if no match.
    """
    match = re.search(EBCDIC_REGEX, payload)
    if match:
        try:
            ebcdic_text = match.group(1).decode('cp500', errors='replace')
            if ebcdic_text.strip():
                return ebcdic_text
        except UnicodeDecodeError:
            pass
    return None


def combined_callback(packet, malicious_ips, modes, seen_ips):
    """
    Unified callback for ASCII and/or EBCDIC traffic.
    - Prints source IP only once, with malicious highlight if needed.
    - Continues to parse ASCII and/or EBCDIC for each packet.
    """
    if packet.haslayer(TCP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        payload = bytes(packet[TCP].payload)
        
        # Only print the IP if we haven't seen it before.
        if src_ip not in seen_ips:
            # Mark malicious or not
            if src_ip in malicious_ips:
                print(f"{RED}[!] Malicious IP connection: {src_ip}{RESET}")
            else:
                print(f"Incoming connection from: {src_ip}")
            
            # Add to seen set
            seen_ips.add(src_ip)
        
        # Even though we only print the IP once,
        # we still parse the payload for ASCII/EBCDIC each time.
        if not payload:
            return
        
        if "ascii" in modes:
            ascii_text = parse_ascii(payload)
            if ascii_text is not None:
                print(f"[ASCII] {ascii_text}")
        
        if "ebcdic" in modes:
            ebcdic_text = parse_ebcdic(payload)
            if ebcdic_text is not None:
                print(f"[EBCDIC] {ebcdic_text}")


###############################################################################
# Sniffers
###############################################################################

def sniff_combined(target, ports, interface, malicious_ips, modes):
    """
    Captures traffic for the given target and ports, using 'combined_callback'
    to parse both ASCII and/or EBCDIC (depending on 'modes').
    """
    # Build a BPF filter for host AND multiple ports.
    # Example: host 192.168.1.100 and tcp and (port 23 or port 3270)
    ports_filter = " or ".join([f"port {p}" for p in ports])
    filter_str = f"host {target} and tcp and ({ports_filter})"

    print(f"Starting capture on interface '{interface}' for {target}:{ports}")
    print(f"Modes: {', '.join(modes)}")
    print("Press Ctrl+C to stop...\n")

    # This set will track which IP addresses we've already printed
    seen_ips = set()

    # Start sniffing
    packets = sniff(
        filter=filter_str,
        iface=interface,
        prn=lambda pkt: combined_callback(pkt, malicious_ips, modes, seen_ips)
    )

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
        # If scapy-ssl_tls is available, you might parse handshake messages, etc.
        print("TLS packet captured (likely encrypted).")

    print(f"Starting TLS capture on interface='{interface}', port=443")
    print("Press Ctrl+C to stop...\n")

    packets = sniff(filter=filter_str, iface=interface, prn=tls_packet_callback)
    wrpcap("tls_traffic.pcap", packets)
    print("Done! TLS packets saved to tls_traffic.pcap.")


###############################################################################
# Main
###############################################################################

def main():
    parser = argparse.ArgumentParser(
        description="Packet Sniffer that can handle ASCII, EBCDIC (3270), or TLS traffic."
    )
    parser.add_argument(
        "TARGET",
        help="Target IP for traffic sniffing (omit if --tls is used).",
        nargs="?",
        default=None
    )
    parser.add_argument(
        "-p", "--ports",
        help="One or more target ports (Default: 3270). Example: -p 23 3270 80",
        nargs="+",
        default=["3270"],
        type=Port
    )
    parser.add_argument(
        "-i", "--iface",
        help="Interface to use (default: tries system default).",
        default=get_default_iface_name_linux()
    )
    parser.add_argument(
        "-m", "--modes",
        help="Which traffic types to parse: ascii, ebcdic, or both. Example: -m ascii ebcdic",
        nargs="+",
        default=["ebcdic"],
        choices=["ebcdic", "ascii"]
    )
    parser.add_argument(
        "--tls", action="store_true",
        help="Capture TLS traffic on port 443 instead of EBCDIC/ASCII. If specified, TARGET/PORTS are ignored."
    )
    parser.add_argument(
        "--malicious-ip-file",
        help="Path to JSON file with malicious IPs. (Default: None)",
        default=None
    )
    args = parser.parse_args()

    # Load malicious IPs from file if provided
    malicious_ips = load_malicious_ips(args.malicious_ip_file)

    # If TLS is specified, ignore target, ports, and modes
    if args.tls:
        if not args.iface:
            print("Could not determine default interface; please specify -i <interface>.")
            sys.exit(1)
        sniff_tls(args.iface)
    else:
        # EBCDIC/ASCII capture
        if not args.TARGET:
            print("Error: You must specify a TARGET unless you use --tls.")
            sys.exit(1)
        if not args.iface:
            print("Could not determine default interface; please specify -i <interface>.")
            sys.exit(1)

        sniff_combined(
            target=args.TARGET,
            ports=args.ports,
            interface=args.iface,
            malicious_ips=malicious_ips,
            modes=args.modes
        )


if __name__ == "__main__":
    main()


