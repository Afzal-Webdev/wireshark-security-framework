# Artifact — A Low-Cost Wireshark-Based Web Security Framework for Non-Expert Users

Reproduction package for the two experiments reported in the paper.

Author: Assad Ur Rehman, Department of Electrical and Computer Engineering,
COMSATS University Islamabad, Wah Campus, Pakistan.

Everything here regenerates from source. No captured traffic is included and none
is required: all packets are generated programmatically, so the results are
reproducible on any machine without access to a network.

---

## Requirements

- Python 3.8 or later
- Scapy — `pip install scapy`
- Wireshark / tshark 4.x — results in the paper were produced with **tshark 4.2.2**
  (Debian/Ubuntu: `sudo apt install tshark`)

Verify tshark is on the path before running Experiment A:

```
tshark --version
```

---

## Experiment A — Filter verification (paper Table II)

Builds three protocol-accurate captures, one per module, each containing the
condition the module targets plus benign control traffic. Then executes every
display filter specified in the paper through the real Wireshark filter engine
and compares the match count against the testbed's known composition.

```
cd experiment_a_testbed
python3 make_testbed.py      # writes module1_arp.pcap, module2_tls_dns.pcap,
                             #        module3_http_tls.pcap, expected.json
python3 verify_filters.py    # runs all 13 checks through tshark
```

Expected final line:

```
13/13 filters verified, 0 failed
```

Also writes `filter_verification.csv`, which is the source of paper Table II.

The three `.pcap` files can be opened directly in the Wireshark GUI to inspect
the packets by hand, or to try the display filters interactively.

**Note on one filter.** The paper reports that `tls.handshake.extensions_type==65037`
is rejected by Wireshark 4.x as syntactically invalid, and that the correct field
name is `tls.handshake.extension.type`. This can be confirmed directly:

```
tshark -r module2_tls_dns.pcap -Y "tls.handshake.extensions_type==65037"
# -> tshark: Constant expression is invalid.

tshark -r module2_tls_dns.pcap -Y "tls.handshake.extension.type==65037"
# -> 1 packet
```

---

## Experiment B — Threshold sensitivity (paper Tables III–V, Figures 1–2)

Generates a 410-second labeled capture with background traffic and five injected
attack episodes, extracts per-second features, and evaluates a threshold detector
under two different state scopings.

```
cd experiment_b_benchmark
python3 generate_traffic.py         # writes synthetic.pcap (~4 MB) + labels.csv
python3 evaluate.py                 # global per-second detector -> results.csv
python3 stateful_scan_detector.py   # per-source sliding-window detector
```

`generate_traffic.py` uses a fixed random seed (42), so the capture and every
number below are deterministic across runs and machines.

### Expected output — `evaluate.py`

```
precision: 0.9904761904761905
recall:    0.65
f1:        0.7849056603773585
fpr:       0.004
```

Per-episode recall (paper Section IV-B2), derived from `results.csv`:

| Episode              | Window (s) | Flagged | Recall | Latency |
|----------------------|-----------|---------|--------|---------|
| Port scan            | 100–129   | 30/30   | 1.000  | 0 s     |
| SYN flood            | 180–204   | 25/25   | 1.000  | 0 s     |
| Spoofed flood        | 250–274   | 25/25   | 1.000  | 0 s     |
| Stealthy scan        | 300–339   | 2/40    | 0.050  | 14 s    |
| Low-rate distributed | 360–399   | 22/40   | 0.550  | 0 s     |

### Expected output — `stateful_scan_detector.py`

```
Stealthy scan window [300,339]: 34/40 seconds correctly flagged, 6 missed
Within the stealthy-scan window, first flagged second: 306  -> latency = 6s
```

This is paper Table IV: recall on the stealthy scan rises from 2/40 to 34/40
when the identical counter is keyed per source IP over a 30-second sliding
window instead of globally per second, with zero false positives across the
full 410-second trace.

### Reproducing the threshold sweep (paper Table V, Figure 2)

```
cd experiment_b_benchmark
python3 - <<'EOF'
from evaluate import load_labels, calibrate, detect, evaluate, PCAP, LABELS_CSV, CALIBRATION_WINDOW
from features import extract_features
import evaluate as ev

labels = load_labels(LABELS_CSV)
feats  = extract_features(PCAP)
base   = calibrate(feats, CALIBRATION_WINDOW)

print(f"{'K':>5} {'prec':>8} {'recall':>8} {'f1':>8} {'fpr':>8}")
for k in [1.5, 2.0, 2.5, 3.0, 4.0, 8.0]:
    ev.K = {m: k for m in ev.K}
    m = evaluate(detect(feats, base), labels)
    print(f"{k:5.1f} {m['precision']:8.3f} {m['recall']:8.3f} {m['f1']:8.3f} {m['fpr']:8.4f}")
EOF
```

Expected:

```
    K     prec   recall       f1      fpr
  1.5    0.720    0.931    0.812   0.2320
  2.0    0.893    0.887    0.890   0.0680
  2.5    0.971    0.844    0.903   0.0160
  3.0    0.984    0.794    0.879   0.0080
  4.0    0.990    0.650    0.785   0.0040
  8.0    1.000    0.500    0.667   0.0000
```

---

## Scope and honest limitations

These captures are **synthetic**. The packets are protocol-accurate — real ARP
opcodes, a real TLS ClientHello carrying a real SNI extension, real HTTP request
bytes, real IANA cipher-suite identifiers — so the filters and counters under test
operate on genuine protocol structure. What is synthetic is the *origin* of the
traffic, not its protocol validity.

Consequently:

- Experiment A establishes that each filter fires on the condition it targets and
  stays silent on the benign controls in the same capture. It does **not**
  establish a false-positive rate on production traffic.
- Experiment B characterizes counter-and-threshold rules on generated traffic with
  known labels. The precision and recall figures are properties of this benchmark,
  not predictions of field performance.

No traffic was captured from any live network. Hostnames and addresses use ranges
reserved for documentation (RFC 5737, RFC 2606); the credentials appearing in the
Module 3 capture are fabricated test values.

---

## File manifest

```
experiment_a_testbed/
  make_testbed.py       generates the three per-module captures
  verify_filters.py     runs all 13 filter checks through tshark
experiment_b_benchmark/
  generate_traffic.py   generates the 410 s labeled benchmark capture
  features.py           streaming per-second feature extraction
  evaluate.py           global per-second threshold detector + metrics
  stateful_scan_detector.py   per-source sliding-window detector
```

Generated files (`*.pcap`, `labels.csv`, `results.csv`, `expected.json`,
`filter_verification.csv`) are not shipped; every script writes them into its own
directory on first run.

---

## License

Released under the MIT License. If you use this artifact, please cite the paper.
