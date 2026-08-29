"""
Builds three small, protocol-accurate synthetic captures, one per framework module.

IMPORTANT (honesty of claim): these are LAB-GENERATED captures, not live traffic.
Every packet is a real, well-formed protocol message (real ARP opcodes, a real
TLS ClientHello with a real SNI extension, real HTTP request bytes, real IANA
cipher-suite identifiers), so the Wireshark display filters under test operate on
genuine protocol structure. What is synthetic is the SOURCE of the traffic, not
the traffic's protocol validity. Each capture deliberately contains BENIGN
control packets alongside the target condition, so a filter that matches
everything is detectably wrong.

Ground truth (expected match counts) is written to expected.json.
"""
import json
from scapy.all import (
    Ether, ARP, IP, TCP, Raw, wrpcap
)

import os
OUT = os.path.dirname(os.path.abspath(__file__))
expected = {}

# ---------------------------------------------------------------- Module 1
# ARP spoofing: a benign exchange, then a conflicting binding for the same IP,
# then gratuitous ARP, then a single MAC claiming many IPs (sweep).
GW_IP, GW_MAC = "192.168.1.1", "00:11:22:33:44:55"
VICTIM_IP, VICTIM_MAC = "192.168.1.50", "aa:bb:cc:dd:ee:01"
ATTACKER_MAC = "de:ad:be:ef:00:99"

m1 = []
t = 1000.0

def push(lst, pkt, ts):
    pkt.time = ts
    lst.append(pkt)

# --- benign: victim asks for gateway, gateway answers (correct MAC)
push(m1, Ether(src=VICTIM_MAC, dst="ff:ff:ff:ff:ff:ff") /
     ARP(op=1, hwsrc=VICTIM_MAC, psrc=VICTIM_IP, pdst=GW_IP), t); t += 0.1
push(m1, Ether(src=GW_MAC, dst=VICTIM_MAC) /
     ARP(op=2, hwsrc=GW_MAC, psrc=GW_IP, hwdst=VICTIM_MAC, pdst=VICTIM_IP), t); t += 5

# --- ATTACK: attacker claims to be the gateway (conflicting IP->MAC binding)
# This is what arp.duplicate-address-detected keys on.
push(m1, Ether(src=ATTACKER_MAC, dst=VICTIM_MAC) /
     ARP(op=2, hwsrc=ATTACKER_MAC, psrc=GW_IP, hwdst=VICTIM_MAC, pdst=VICTIM_IP), t); t += 1
push(m1, Ether(src=ATTACKER_MAC, dst=VICTIM_MAC) /
     ARP(op=2, hwsrc=ATTACKER_MAC, psrc=GW_IP, hwdst=VICTIM_MAC, pdst=VICTIM_IP), t); t += 1

# --- ATTACK: gratuitous ARP (psrc == pdst), unsolicited
push(m1, Ether(src=ATTACKER_MAC, dst="ff:ff:ff:ff:ff:ff") /
     ARP(op=2, hwsrc=ATTACKER_MAC, psrc=GW_IP, pdst=GW_IP), t); t += 1

# --- ATTACK: sweep — one MAC claims 8 distinct IPs within 30s
sweep_ips = [f"192.168.1.{i}" for i in range(60, 68)]
for ip in sweep_ips:
    push(m1, Ether(src=ATTACKER_MAC, dst="ff:ff:ff:ff:ff:ff") /
         ARP(op=2, hwsrc=ATTACKER_MAC, psrc=ip, pdst=ip), t); t += 0.5

wrpcap(f"{OUT}/module1_arp.pcap", m1)
expected["module1"] = {
    "total_packets": len(m1),
    "benign_arp_packets": 2,
    "conflicting_binding_replies": 2,
    "gratuitous_arp_total": 1 + len(sweep_ips),  # sweep packets are also gratuitous
    "distinct_ips_claimed_by_attacker_mac": 1 + len(sweep_ips),  # GW_IP + sweep
    "attacker_mac": ATTACKER_MAC,
}

# ---------------------------------------------------------------- Module 2
# HTTPS metadata: real TLS ClientHello records carrying a real SNI extension,
# plus plaintext DNS queries. One ClientHello includes an ECH extension (65037)
# to verify the framework distinguishes protected from exposed sessions.

def tls_client_hello(sni: str, include_ech: bool = False) -> bytes:
    """Construct a minimal but structurally valid TLS 1.2/1.3 ClientHello."""
    # --- SNI extension (type 0x0000)
    host = sni.encode()
    server_name = b"\x00" + len(host).to_bytes(2, "big") + host   # type=host_name
    sni_list = len(server_name).to_bytes(2, "big") + server_name
    ext_sni = b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list

    exts = ext_sni
    if include_ech:
        ech_payload = b"\x00" * 8
        exts += (65037).to_bytes(2, "big") + len(ech_payload).to_bytes(2, "big") + ech_payload

    # supported_versions -> TLS 1.3
    sv = b"\x02\x03\x04"
    exts += b"\x00\x2b" + len(sv).to_bytes(2, "big") + sv

    body = b"\x03\x03"                    # client_version TLS1.2
    body += b"\x11" * 32                  # random
    body += b"\x00"                       # session_id length 0
    cipher_suites = b"\x13\x01\x13\x02"   # TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
    body += len(cipher_suites).to_bytes(2, "big") + cipher_suites
    body += b"\x01\x00"                   # compression: null
    body += len(exts).to_bytes(2, "big") + exts

    hs = b"\x01" + len(body).to_bytes(3, "big") + body        # handshake: ClientHello
    rec = b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs   # record: handshake
    return rec

def dns_query(name: str) -> bytes:
    """Minimal DNS query message (used over UDP/53)."""
    q = b""
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + b"\x00\x01" + b"\x00\x01"     # QTYPE=A, QCLASS=IN
    header = b"\xab\xcd" + b"\x01\x00" + b"\x00\x01" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00"
    return header + q

from scapy.all import UDP
m2 = []
t = 2000.0
CLIENT = "192.168.1.50"
RESOLVER = "192.168.1.1"

exposed_hosts = ["bank.example.com", "mail.example.org", "health.example.net"]
for i, h in enumerate(exposed_hosts):
    # plaintext DNS lookup for the host
    push(m2, Ether() / IP(src=CLIENT, dst=RESOLVER) / UDP(sport=40000 + i, dport=53) /
         Raw(load=dns_query(h)), t); t += 0.2
    # TLS ClientHello exposing the same host in SNI
    push(m2, Ether() / IP(src=CLIENT, dst=f"93.184.216.{10+i}") /
         TCP(sport=50000 + i, dport=443, flags="PA", seq=1) /
         Raw(load=tls_client_hello(h)), t); t += 0.5

# one ECH-protected session (SNI present but session is protected)
push(m2, Ether() / IP(src=CLIENT, dst="93.184.216.99") /
     TCP(sport=51000, dport=443, flags="PA", seq=1) /
     Raw(load=tls_client_hello("private.example.com", include_ech=True)), t); t += 0.5

wrpcap(f"{OUT}/module2_tls_dns.pcap", m2)
expected["module2"] = {
    "total_packets": len(m2),
    "plaintext_dns_queries": len(exposed_hosts),
    "client_hellos_total": len(exposed_hosts) + 1,
    "client_hellos_with_ech": 1,
    "hostnames_exposed_via_sni": len(exposed_hosts),
    "exposed_hosts": exposed_hosts,
}

# ---------------------------------------------------------------- Module 3
# Insecure HTTP / weak TLS: plaintext credential POST, HTTP Basic auth,
# a TLS 1.0 handshake, and a ClientHello offering RC4/DES/NULL suites.
m3 = []
t = 3000.0
SERVER = "203.0.113.10"

# --- ATTACK/FINDING: credentials in a plaintext POST body
body = "username=alice&password=hunter2"
http_post = (
    "POST /login HTTP/1.1\r\n"
    f"Host: legacy.example.com\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    f"Content-Length: {len(body)}\r\n\r\n{body}"
)
push(m3, Ether() / IP(src=CLIENT, dst=SERVER) /
     TCP(sport=52000, dport=80, flags="PA", seq=1) / Raw(load=http_post.encode()), t); t += 1

# --- FINDING: HTTP Basic Authentication header (base64 of alice:hunter2)
http_basic = (
    "GET /admin HTTP/1.1\r\n"
    "Host: legacy.example.com\r\n"
    "Authorization: Basic YWxpY2U6aHVudGVyMg==\r\n\r\n"
)
push(m3, Ether() / IP(src=CLIENT, dst=SERVER) /
     TCP(sport=52001, dport=80, flags="PA", seq=1) / Raw(load=http_basic.encode()), t); t += 1

# --- BENIGN CONTROL: ordinary HTTP GET, no credentials (must NOT match)
http_plain = "GET /index.html HTTP/1.1\r\nHost: legacy.example.com\r\n\r\n"
push(m3, Ether() / IP(src=CLIENT, dst=SERVER) /
     TCP(sport=52002, dport=80, flags="PA", seq=1) / Raw(load=http_plain.encode()), t); t += 1

def tls_hello_version(rec_ver: bytes, client_ver: bytes, suites: bytes) -> bytes:
    exts = b"\x00\x00\x00\x00"  # empty SNI ext to keep structure valid
    body = client_ver + b"\x22" * 32 + b"\x00"
    body += len(suites).to_bytes(2, "big") + suites
    body += b"\x01\x00"
    body += len(exts).to_bytes(2, "big") + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16" + rec_ver + len(hs).to_bytes(2, "big") + hs

# --- FINDING: TLS 1.0 (0x0301) negotiation
push(m3, Ether() / IP(src=CLIENT, dst=SERVER) /
     TCP(sport=53000, dport=443, flags="PA", seq=1) /
     Raw(load=tls_hello_version(b"\x03\x01", b"\x03\x01", b"\x00\x2f")), t); t += 1

# --- FINDING: weak cipher suites offered
#   0x0004 RSA_WITH_RC4_128_MD5, 0x0005 RSA_WITH_RC4_128_SHA,
#   0x0009 RSA_WITH_DES_CBC_SHA, 0x0001 RSA_WITH_NULL_MD5
weak = b"\x00\x04\x00\x05\x00\x09\x00\x01"
push(m3, Ether() / IP(src=CLIENT, dst=SERVER) /
     TCP(sport=53001, dport=443, flags="PA", seq=1) /
     Raw(load=tls_hello_version(b"\x03\x01", b"\x03\x03", weak)), t); t += 1

# --- BENIGN CONTROL: modern TLS 1.3 suites only (must NOT match weak filter)
push(m3, Ether() / IP(src=CLIENT, dst=SERVER) /
     TCP(sport=53002, dport=443, flags="PA", seq=1) /
     Raw(load=tls_hello_version(b"\x03\x01", b"\x03\x03", b"\x13\x01\x13\x02")), t); t += 1

wrpcap(f"{OUT}/module3_http_tls.pcap", m3)
expected["module3"] = {
    "total_packets": len(m3),
    "plaintext_credential_posts": 1,
    "http_basic_auth_headers": 1,
    "benign_http_requests": 1,
    "tls10_or_ssl3_hellos": 1,
    "hellos_offering_weak_ciphers": 1,
    "benign_modern_hellos": 1,
}

with open(f"{OUT}/expected.json", "w") as f:
    json.dump(expected, f, indent=2)

print(json.dumps(expected, indent=2))
print("\nWrote module1_arp.pcap, module2_tls_dns.pcap, module3_http_tls.pcap")
