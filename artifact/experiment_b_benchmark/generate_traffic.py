"""
Generates a single labeled pcap with 4 regimes back to back:
  [0,100)    normal only
  [100,130)  normal + PORT SCAN   (attacker sweeps ports on one victim)
  [130,180)  normal only
  [180,205)  normal + SYN FLOOD   (few sources, massive SYN volume, one victim:port)
  [205,250)  normal only
  [250,275)  normal + SPOOFED FLOOD (thousands of forged src IPs, low volume each)
  [275,300)  normal only

Ground truth is written to labels.csv: one row per second, with the active attack type.
Packet timestamps are jittered within each second so pps isn't perfectly uniform (more realistic).
"""
import random
import csv
from scapy.all import IP, TCP, UDP, ICMP, wrpcap
import os
BASE = os.path.dirname(os.path.abspath(__file__))

random.seed(42)

TOTAL_SECONDS = 410
INTERNAL_HOSTS = [f"10.0.1.{i}" for i in range(2, 40)]
SERVERS = [f"10.0.0.{i}" for i in range(10, 15)]
INTERNET_HOSTS = [f"203.0.113.{i}" for i in range(1, 60)]
COMMON_PORTS = [80, 443, 22, 53, 123, 5432, 3306, 8080]

VICTIM = "10.0.0.10"
SCANNER = "198.51.100.77"
FLOODER_POOL = ["198.51.100.201", "198.51.100.202", "198.51.100.203"]  # small = botnet-lite

packets = []
rows = []

def add_pkt(pkt, t):
    pkt.time = t
    packets.append(pkt)

def normal_second(t0):
    """Background traffic for one second: a handful of realistic flows."""
    n = random.randint(60, 100)  # baseline pps
    tcp_syn = tcp_synack = tcp_other = udp_c = icmp_c = 0
    for _ in range(n):
        jitter = random.random()
        t = t0 + jitter
        r = random.random()
        if r < 0.55:  # TCP flow traffic
            src = random.choice(INTERNAL_HOSTS)
            dst = random.choice(SERVERS + INTERNET_HOSTS)
            # mostly common service ports, occasional oddball port so uniq_ports/sec
            # has real (non-zero) variance instead of a degenerate constant
            if random.random() < 0.08:
                dport = random.randint(1, 60000)
            else:
                dport = random.choice([80, 443, 22, 8080, 5432])
            leg = random.random()
            if leg < 0.15:
                flags = "S"; tcp_syn += 1
            elif leg < 0.30:
                flags = "SA"; tcp_synack += 1
            elif leg < 0.45:
                flags = "A"; tcp_other += 1
            elif leg < 0.55:
                flags = "PA"; tcp_other += 1
            else:
                flags = "A"; tcp_other += 1
            add_pkt(IP(src=src, dst=dst) / TCP(sport=random.randint(1024, 65000), dport=dport, flags=flags), t)
        elif r < 0.85:  # UDP: DNS/NTP
            src = random.choice(INTERNAL_HOSTS)
            dst = random.choice(SERVERS)
            dport = random.choice([53, 123])
            add_pkt(IP(src=src, dst=dst) / UDP(sport=random.randint(1024, 65000), dport=dport), t)
            udp_c += 1
        else:  # ICMP ping noise
            src = random.choice(INTERNAL_HOSTS)
            dst = random.choice(SERVERS)
            add_pkt(IP(src=src, dst=dst) / ICMP(), t)
            icmp_c += 1
    return dict(pps=n, tcp_syn=tcp_syn, tcp_synack=tcp_synack, tcp_other=tcp_other, udp=udp_c, icmp=icmp_c)

def port_scan_second(t0):
    """Attacker sweeps ~150 unique ports on VICTIM, SYN only, almost nothing comes back."""
    n = random.randint(120, 160)
    used_ports = random.sample(range(1, 65000), n)
    for p in used_ports:
        t = t0 + random.random()
        add_pkt(IP(src=SCANNER, dst=VICTIM) / TCP(sport=random.randint(1024, 65000), dport=p, flags="S"), t)
    return n

def syn_flood_second(t0):
    """3 sources hammer VICTIM:80 with SYNs, negligible SYN-ACKs return (backlog exhausted)."""
    n = random.randint(700, 900)
    for _ in range(n):
        t = t0 + random.random()
        src = random.choice(FLOODER_POOL)
        add_pkt(IP(src=src, dst=VICTIM) / TCP(sport=random.randint(1024, 65000), dport=80, flags="S"), t)
    return n

def spoofed_flood_second(t0):
    """Thousands of forged, essentially-never-repeating src IPs, 1 packet each, at VICTIM:80."""
    n = random.randint(600, 800)
    for _ in range(n):
        t = t0 + random.random()
        src = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        add_pkt(IP(src=src, dst=VICTIM) / TCP(sport=random.randint(1024, 65000), dport=80, flags="S"), t)
    return n

def stealthy_scan_second(t0, used_ports_ever):
    """
    Evasive version of the scan: only 3-5 NEW ports/sec on top of the ~10.6/sec the
    baseline already touches -> total sits around 14-16, comfortably under the
    18.85 four-sigma threshold. Slow, but it still sweeps ~150 ports over the window.
    """
    n = random.randint(3, 5)
    candidates = [p for p in random.sample(range(1, 65000), n * 3) if p not in used_ports_ever]
    ports = candidates[:n]
    used_ports_ever.update(ports)
    for p in ports:
        t = t0 + random.random()
        add_pkt(IP(src=SCANNER, dst=VICTIM) / TCP(sport=random.randint(1024, 65000), dport=p, flags="S"), t)
    return n

LOW_RATE_BOTS = [f"198.51.{110+i}.{50+i}" for i in range(6)]  # small, FIXED pool -> low uniq_src_ips footprint

def low_rate_distributed_second(t0):
    """
    Evasive distributed probe: only 6 fixed source IPs (not one-new-IP-per-packet),
    each sending 3-4 pkts/sec -> adds ~18-24 pps and only ~6 to uniq_src_ips, both
    of which land under their respective thresholds (122.6 pps / 41.9 uniq_src_ips)
    when combined with baseline. Present continuously, but individually invisible
    to a per-second static threshold.
    """
    total_added = 0
    for src in LOW_RATE_BOTS:
        for _ in range(random.randint(3, 4)):
            t = t0 + random.random()
            add_pkt(IP(src=src, dst=VICTIM) / TCP(sport=random.randint(1024, 65000), dport=80, flags="S"), t)
            total_added += 1
    return total_added

used_ports_ever = set()

for sec in range(TOTAL_SECONDS):
    stats = normal_second(sec)
    label = "normal"
    extra_ports = 0
    if 100 <= sec < 130:
        extra_ports = port_scan_second(sec)
        label = "port_scan"
    elif 180 <= sec < 205:
        syn_flood_second(sec)
        label = "syn_flood"
    elif 250 <= sec < 275:
        spoofed_flood_second(sec)
        label = "spoofed_flood"
    elif 300 <= sec < 340:
        stealthy_scan_second(sec, used_ports_ever)
        label = "stealthy_scan"
    elif 360 <= sec < 400:
        low_rate_distributed_second(sec)
        label = "low_rate_distributed"
    rows.append({"second": sec, "label": label})

print(f"Total packets generated: {len(packets)}")
packets.sort(key=lambda p: p.time)
wrpcap(os.path.join(BASE, "synthetic.pcap"), packets)

with open(os.path.join(BASE, "labels.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["second", "label"])
    w.writeheader()
    w.writerows(rows)

print("Wrote synthetic.pcap and labels.csv")
