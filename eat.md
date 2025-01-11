```markdown
# EAT.PY - Technical Manual

## 1. Overview

**`EAT.py`** is a Python-based network sniffer leveraging **Scapy**. It can intercept TCP packets in real time and optionally decode payloads as **ASCII** or **EBCDIC** (commonly used on mainframes, e.g., 3270 terminals), or capture **TLS (SSL) traffic** on port 443. In the case of TLS, the data is typically encrypted; one can optionally perform a man-in-the-middle (MITM) attack (in an **ethical** or **authorized** penetration test scenario) to decrypt that data if you have the necessary private key or session secrets.
NOTE: - PLEASE SEE THE PDF FILE FOR THE LATEST ADDITIONAL FEATURES.

### Key Features

- **Captures inbound/outbound TCP traffic** for specified interfaces and ports.
- **Decodes EBCDIC** (`cp500`) for 3270-like traffic.
- **Decodes ASCII** for cleartext protocols (e.g., Telnet, FTP, etc.).
- **Captures TLS** (encrypted) traffic on port 443 (decryption requires additional MITM setup).
- **Saves all captured packets** to a `.pcap` file for later analysis.

### Ethical Usage

1. **Penetration Testing**: In an **authorized** environment (e.g., your lab or with explicit permission from the network owner), you can observe how easily unencrypted credentials may be intercepted.
2. **Troubleshooting & Debugging**: Network admins or developers can use `EAT.py` to troubleshoot ASCII-based protocols and confirm whether encrypted channels are properly configured.
3. **Security Research**: Validate and demonstrate the impact of transmitting sensitive data without encryption.

> **Warning**: Always ensure you have **explicit permission** before sniffing or intercepting traffic on any network. Unauthorized sniffing can be illegal.

---

## 2. Components & Requirements

1. **Python 3.x**: Ensure you have a modern Python environment (3.6+ recommended).
2. **Scapy**: This script depends on Scapy to capture, parse, and write PCAP files. Install via:

   pip install scapy

3. **Permissions**: On many systems, sniffing requires elevated privileges (e.g., `sudo` on Linux).

### Optional Components for TLS Decryption

- **scapy-ssl_tls** (or similar plugin): For partial parsing of SSL/TLS if you want to see handshake messages in detail.
- **ARPSPOOF or Ettercap**: Tools that help reroute traffic to your system if you need to run a MITM attack on a switched LAN.
- **MITM Setup**: A custom **certificate** and **key** (or a CA certificate you install on the client) so that you can **decrypt** the traffic in real time.

---

## 3. How It Works

`EAT.py` uses **Scapy** to:

1. **Create a capture filter** (e.g., `host <targetIP> and port <port>`).
2. **Sniff packets** on the specified interface (e.g., `eth0` or `wlan0`).
3. **Decode the payload**:
   - **EBCDIC** (`cp500`) if `--encoding ebcdic` is specified.
   - **ASCII** if `--encoding ascii` is used.
   - **TLS** capture on port 443 if `--tls` is specified (remains encrypted unless a MITM is in place).
4. **Write all packets** to `<mode>_traffic.pcap`.

---

## 4. Usage Examples

Below are some typical command-line examples. 

### 4.1 Capturing EBCDIC (e.g., 3270 Traffic)


python3 EAT.py 192.168.1.10 -p 3270 --encoding ebcdic


- **Target**: `192.168.1.10`
- **Port**: `3270`
- **Encoding**: EBCDIC
- **Output**: Captures any inbound/outbound TCP traffic on port 3270 and attempts to decode EBCDIC text in real time.

### 4.2 Capturing ASCII (e.g., Telnet on Port 23)


python3 EAT.py 192.168.1.50 -p 23 --encoding ascii


- **Target**: `192.168.1.50`
- **Port**: `23`
- **Encoding**: ASCII
- **Output**: Decodes all ASCII data in real time (useful for Telnet, FTP control channel, HTTP, SMTP, etc.).

### 4.3 Capturing TLS/SSL on Port 443


python3 EAT.py --tls -i eth0


- **TLS flag**: Ignores the `TARGET` and `PORT` parameters, defaulting to port **443**.
- **Output**: Saves encrypted packets to `tls_traffic.pcap`. By default, you see ciphertext in real time.
- **Decryption**: Requires a MITM approach or key-logging to see plaintext.

---

## 5. MITM Setup for TLS Decryption (Optional)

### 5.1 Creating or Using a Certificate & Key

If you have a **test environment** and can install your own **root CA** or certificate on the client:

1. **Create a CA (once)**:

   openssl genrsa -out myCA.key 2048
   openssl req -x509 -new -nodes -key myCA.key -sha256 -days 365 -out myCA.crt

   This is your **root certificate**.

2. **Trust your CA**:
   - On the client machine, import `myCA.crt` into the trusted certificate store (varies by OS).

3. **Generate a Server Certificate** using your CA:

   openssl genrsa -out mitm_server.key 2048
   openssl req -new -key mitm_server.key -out mitm_server.csr
   openssl x509 -req -in mitm_server.csr -CA myCA.crt -CAkey myCA.key \
     -CAcreateserial -out mitm_server.crt -days 365 -sha256

   You now have `mitm_server.crt` and `mitm_server.key` that can be used by your MITM proxy.

4. **Run a MITM proxy** (e.g., a custom Python script, or a tool like `mitmproxy`, `bettercap`, or `sslsplit`) that presents `mitm_server.crt` to the client. Once the proxy intercepts traffic, you can see plaintext in real time or forward it to **`EAT.py`** in unencrypted form.

### 5.2 ARP Spoofing / Ettercap

On a local network, you can use **`arpspoof`** or **`Ettercap`** to trick the client and router into sending traffic to your machine:

- **arpspoof** example:

  # 1. Enable IP forwarding so you can forward traffic
  echo 1 > /proc/sys/net/ipv4/ip_forward

  # 2. Start arpspoof (client is 192.168.1.50, gateway is 192.168.1.1)
  arpspoof -i eth0 -t 192.168.1.50 192.168.1.1
  arpspoof -i eth0 -t 192.168.1.1 192.168.1.50


- **Ettercap** example:

  ettercap -T -M arp:remote /192.168.1.50// /192.168.1.1//


### 5.3 Viewing Plaintext from MITM

Once you have a successful MITM setup:

1. **All traffic** from the client to the server flows through your system.
2. If your MITM terminates TLS, you have **plaintext** in the middle.
3. You can **forward that plaintext** to a local port or process it further with `EAT.py`.

---

## 6. Frequently Asked Questions

1. **Why do I only see encrypted data on port 443?**
   - TLS traffic is encrypted end-to-end. You need a MITM or session key logs to see the plaintext.

2. **What if I only see partial ASCII or control characters?**
   - Some protocols (like Telnet) include negotiation bytes. `EAT.py` prints raw payloads, so you may see extra control codes. Tools like Wireshark or specialized parsers can reassemble or strip these.

3. **Why do I see garbled text when expecting ASCII?**
   - Confirm the traffic is truly unencrypted and that you have the correct capture filter. Some “plain-text” protocols still include overhead or binary data.

4. **Can I get in trouble for running this?**
   - **Yes**, if it’s done on networks you don’t own or have permission to test. Only run sniffers with explicit authorization.

---

## 7. Conclusion

**`EAT.py`** is a versatile script for capturing and decoding traffic in multiple formats:

- **EBCDIC** mode helps with mainframe/3270 data.
- **ASCII** mode is useful for many unencrypted protocols.
- **TLS** capture mode gathers encrypted streams, which can be decrypted only if you implement a **man-in-the-middle** scenario or extract TLS session keys.

By combining **`EAT.py`** with standard MITM tools like **arpspoof** and **Ettercap**, or by setting up a **trusted certificate** on the client, you can ethically demonstrate (within an authorized penetration test or lab environment) how easily plaintext credentials or data can be exposed—or how effectively TLS encryption can protect data against interception.
```
