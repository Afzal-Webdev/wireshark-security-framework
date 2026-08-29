import math
from collections import defaultdict
from scapy.all import PcapReader, IP, TCP, UDP, ICMP
import os
BASE = os.path.dirname(os.path.abspath(__file__))

def extract_features(pcap_path, bin_size=1.0):
    """
    Streams the pcap (doesn't load it all into memory) and returns a dict:
      second -> {pps, uniq_ports, uniq_src_ips, syn, synack, tcp, udp, icmp, other}
    """
    bins = defaultdict(lambda: {
        "pps": 0, "ports": set(), "src_ips": set(),
        "syn": 0, "synack": 0, "tcp": 0, "udp": 0, "icmp": 0, "other": 0,
    })

    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            if IP not in pkt:
                continue
            sec = int(math.floor(float(pkt.time) / bin_size) * bin_size)
            b = bins[sec]
            b["pps"] += 1
            b["src_ips"].add(pkt[IP].src)

            if TCP in pkt:
                b["tcp"] += 1
                b["ports"].add(pkt[TCP].dport)
                flags = pkt[TCP].flags
                if flags == "S":
                    b["syn"] += 1
                elif flags == "SA":
                    b["synack"] += 1
            elif UDP in pkt:
                b["udp"] += 1
                b["ports"].add(pkt[UDP].dport)
            elif ICMP in pkt:
                b["icmp"] += 1
            else:
                b["other"] += 1

    out = {}
    for sec, b in bins.items():
        total = b["pps"] or 1
        out[sec] = {
            "pps": b["pps"],
            "uniq_ports": len(b["ports"]),
            "uniq_src_ips": len(b["src_ips"]),
            "syn": b["syn"],
            "synack": b["synack"],
            "syn_synack_ratio": b["syn"] / (b["synack"] + 1),
            "tcp_pct": b["tcp"] / total,
            "udp_pct": b["udp"] / total,
            "icmp_pct": b["icmp"] / total,
            "other_pct": b["other"] / total,
        }
    return out

if __name__ == "__main__":
    feats = extract_features(os.path.join(BASE, "synthetic.pcap"))
    for sec in sorted(feats)[:5]:
        print(sec, feats[sec])
    print("...")
    print("total seconds with traffic:", len(feats))
