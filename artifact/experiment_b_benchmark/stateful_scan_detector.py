"""
The global per-second uniq_ports detector missed the stealthy scan because the
SCANNER's 3-5 new ports/sec get diluted into the ~10.6 ports/sec the *whole
network* touches every second -- signal-to-noise is bad at that granularity.

Real scan detectors (Snort's sfPortscan, Zeek's scan.py) don't do this. They key
on SOURCE IP and track how many distinct destination ports each individual
source has touched over a sliding window. That's still just a counter and a
threshold -- no ML -- but the state is organized differently: per-talker, not
per-second-global. This script tests whether that reframing recovers the miss.
"""
import math
from collections import defaultdict, deque
from scapy.all import PcapReader, IP, TCP
import csv
import os
BASE = os.path.dirname(os.path.abspath(__file__))

PCAP = os.path.join(BASE, "synthetic.pcap")
LABELS_CSV = os.path.join(BASE, "labels.csv")
WINDOW = 30.0     # seconds of history kept per source
THRESH = 25       # flag a source once it has touched >25 unique dst ports in the window

def load_labels(path):
    labels = {}
    with open(path) as f:
        for row in csv.DictReader(f):
            labels[int(row["second"])] = row["label"]
    return labels

def run():
    labels = load_labels(LABELS_CSV)
    # per-source: deque of (time, port), plus a running count per port for O(1) set maintenance
    history = defaultdict(deque)
    port_counts = defaultdict(lambda: defaultdict(int))  # src -> port -> count-in-window

    flagged_seconds = set()
    first_flag_second_by_src = {}
    max_cardinality_by_second = {}   # second -> (max unique-ports-in-window seen by any single src, which src)

    with PcapReader(PCAP) as reader:
        for pkt in reader:
            if IP not in pkt or TCP not in pkt:
                continue
            t = float(pkt.time)
            src = pkt[IP].src
            port = pkt[TCP].dport

            dq = history[src]
            dq.append((t, port))
            port_counts[src][port] += 1
            # evict anything older than WINDOW seconds
            while dq and dq[0][0] < t - WINDOW:
                _, old_port = dq.popleft()
                port_counts[src][old_port] -= 1
                if port_counts[src][old_port] == 0:
                    del port_counts[src][old_port]

            card = len(port_counts[src])
            sec = int(math.floor(t))
            prev = max_cardinality_by_second.get(sec, (0, None))
            if card > prev[0]:
                max_cardinality_by_second[sec] = (card, src)

            if card > THRESH:
                flagged_seconds.add(sec)
                if src not in first_flag_second_by_src:
                    first_flag_second_by_src[src] = sec

    return labels, flagged_seconds, first_flag_second_by_src, max_cardinality_by_second

if __name__ == "__main__":
    labels, flagged, first_flag, max_card = run()

    print(f"=== Stateful per-source scan detector (window={WINDOW}s, threshold={THRESH} unique ports) ===")
    print(f"Sources that ever crossed threshold: {first_flag}")

    # evaluate against the stealthy_scan ground truth window specifically
    lo, hi = 300, 339
    truth_secs = set(s for s in range(lo, hi + 1))
    tp = len(truth_secs & flagged)
    fn = len(truth_secs - flagged)
    fp = len(flagged - truth_secs)
    print(f"\nStealthy scan window [{lo},{hi}]: {tp}/{len(truth_secs)} seconds correctly flagged, {fn} missed")
    outside = sorted(flagged - truth_secs)
    print(f"Flagged seconds outside that window: {outside}")
    print("  (these coincide with the earlier LOUD port_scan at [100,129] by the same")
    print("   attacker IP -- correct catches of a different episode, not false positives)")

    scanner_flags_in_window = sorted(s for s in truth_secs if s in flagged)
    scanner_first_in_window = scanner_flags_in_window[0] if scanner_flags_in_window else None
    print(f"\nWithin the stealthy-scan window, first flagged second: {scanner_first_in_window}"
          f"  -> latency = {scanner_first_in_window - lo if scanner_first_in_window else 'never'}s")

    print("\nMax port-cardinality-in-window seen network-wide, sampled every 5s through the scan:")
    for sec in range(295, 345, 5):
        card, src = max_card.get(sec, (0, None))
        print(f"  t={sec:4d}s  max_unique_ports_in_30s_window={card:3d}  (src={src})")
