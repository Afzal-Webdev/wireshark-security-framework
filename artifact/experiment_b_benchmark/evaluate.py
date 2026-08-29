import csv
import statistics as st
from features import extract_features
import os
BASE = os.path.dirname(os.path.abspath(__file__))

PCAP = os.path.join(BASE, "synthetic.pcap")
LABELS_CSV = os.path.join(BASE, "labels.csv")
CALIBRATION_WINDOW = (0, 60)   # seconds assumed attack-free, used to learn "normal"
K = {"pps": 4.0, "uniq_ports": 4.0, "syn_synack_ratio": 4.0, "uniq_src_ips": 4.0}

def load_labels(path):
    labels = {}
    with open(path) as f:
        for row in csv.DictReader(f):
            labels[int(row["second"])] = row["label"]
    return labels

def calibrate(feats, window):
    lo, hi = window
    cal = {k: [] for k in K}
    for sec, f in feats.items():
        if lo <= sec < hi:
            for k in K:
                cal[k].append(f[k])
    stats = {}
    for k, vals in cal.items():
        mean = st.mean(vals)
        std = st.pstdev(vals) or 1e-6
        stats[k] = (mean, std)
    return stats

def zscore(x, mean, std):
    return (x - mean) / std

def detect(feats, baseline):
    """Returns per-second: flagged bool, z-scores, predicted attack type."""
    results = {}
    for sec, f in feats.items():
        z = {k: zscore(f[k], *baseline[k]) for k in K}
        flagged = any(z[k] > K[k] for k in K)

        pred_type = "normal"
        if flagged:
            if z["uniq_src_ips"] > K["uniq_src_ips"] and z["uniq_src_ips"] >= z["uniq_ports"]:
                pred_type = "spoofed_flood"
            elif z["uniq_ports"] > K["uniq_ports"] and z["uniq_ports"] > z["uniq_src_ips"]:
                pred_type = "port_scan"
            elif z["pps"] > K["pps"] or z["syn_synack_ratio"] > K["syn_synack_ratio"]:
                pred_type = "syn_flood"
            else:
                pred_type = "anomaly"
        results[sec] = {"flagged": flagged, "z": z, "pred_type": pred_type, "raw": f}
    return results

def evaluate(results, labels):
    TP = FP = TN = FN = 0
    subtype_correct = 0
    subtype_total = 0
    for sec, r in results.items():
        truth_attack = labels.get(sec, "normal") != "normal"
        pred_attack = r["flagged"]
        if truth_attack and pred_attack:
            TP += 1
        elif truth_attack and not pred_attack:
            FN += 1
        elif not truth_attack and pred_attack:
            FP += 1
        else:
            TN += 1
        if truth_attack and pred_attack:
            subtype_total += 1
            if r["pred_type"] == labels[sec]:
                subtype_correct += 1

    precision = TP / (TP + FP) if (TP + FP) else float("nan")
    recall = TP / (TP + FN) if (TP + FN) else float("nan")
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else float("nan")
    fpr = FP / (FP + TN) if (FP + TN) else float("nan")
    subtype_acc = subtype_correct / subtype_total if subtype_total else float("nan")
    return dict(TP=TP, FP=FP, TN=TN, FN=FN, precision=precision, recall=recall,
                f1=f1, fpr=fpr, subtype_accuracy=subtype_acc)

def episode_latency(results, labels):
    seconds = sorted(labels)
    blocks = []
    cur_label, cur_start = None, None
    for s in seconds:
        lab = labels[s]
        if lab != "normal" and lab != cur_label:
            if cur_label is not None:
                blocks.append((cur_label, cur_start, s - 1))
            cur_label, cur_start = lab, s
        elif lab == "normal" and cur_label is not None:
            blocks.append((cur_label, cur_start, s - 1))
            cur_label, cur_start = None, None
    if cur_label is not None:
        blocks.append((cur_label, cur_start, seconds[-1]))

    report = []
    for lab, start, end in blocks:
        latency = None
        for s in range(start, end + 1):
            if results.get(s, {}).get("flagged"):
                latency = s - start
                break
        report.append({"attack": lab, "start": start, "end": end, "latency_s": latency})
    return report

if __name__ == "__main__":
    labels = load_labels(LABELS_CSV)
    feats = extract_features(PCAP)
    baseline = calibrate(feats, CALIBRATION_WINDOW)

    print("=== Baseline (learned from seconds 0-59, assumed attack-free) ===")
    for k, (mean, std) in baseline.items():
        print(f"  {k:20s} mean={mean:8.3f}  std={std:8.3f}  threshold(mean+{K[k]}*std)={mean + K[k]*std:8.3f}")

    results = detect(feats, baseline)
    metrics = evaluate(results, labels)
    print("\n=== Detection metrics (per-second, binary attack-vs-normal) ===")
    for k, v in metrics.items():
        print(f"  {k}: {v}")

    print("\n=== Per-episode detection latency ===")
    for ep in episode_latency(results, labels):
        print(f"  {ep['attack']:15s} window=[{ep['start']},{ep['end']}]  latency={ep['latency_s']}s")

    with open(os.path.join(BASE, "results.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["second", "truth", "pred_flagged", "pred_type", "pps", "uniq_ports",
                    "uniq_src_ips", "syn_synack_ratio"])
        for sec in sorted(results):
            r = results[sec]
            w.writerow([sec, labels.get(sec, "normal"), r["flagged"], r["pred_type"],
                        r["raw"]["pps"], r["raw"]["uniq_ports"], r["raw"]["uniq_src_ips"],
                        round(r["raw"]["syn_synack_ratio"], 3)])
    print("\nWrote results.csv")
