"""
Runs every display filter specified in the framework against the synthetic
testbed captures, using the real tshark/Wireshark filter engine, and compares
the match count to the testbed's ground truth.

This verifies FILTER CORRECTNESS (does the rule fire on the condition it
targets, and stay silent on benign controls). It does NOT establish
false-positive rates on production traffic -- see paper Section VII.
"""
import json
import subprocess
import csv

import os
TB = os.path.dirname(os.path.abspath(__file__))

# (module, finding, pcap, filter, expected_matches, note)
TESTS = [
    ("1", "Conflicting IP-to-MAC binding", "module1_arp.pcap",
     "arp.duplicate-address-detected", 3,
     "2 spoofed replies + 1 gratuitous reply for the same IP"),

    ("1", "Gratuitous ARP", "module1_arp.pcap",
     "arp.opcode==2 && arp.src.proto_ipv4==arp.dst.proto_ipv4", 9,
     "1 gateway impersonation + 8 sweep packets"),

    ("1", "Benign ARP not flagged", "module1_arp.pcap",
     "arp && !arp.duplicate-address-detected && "
     "!(arp.opcode==2 && arp.src.proto_ipv4==arp.dst.proto_ipv4)", 2,
     "control: the legitimate request/reply pair must not match attack filters"),

    ("2", "Hostname exposed via SNI", "module2_tls_dns.pcap",
     "tls.handshake.type==1 && tls.handshake.extensions_server_name", 4,
     "all ClientHellos carry an SNI value"),

    ("2", "Session protected by ECH", "module2_tls_dns.pcap",
     "tls.handshake.type==1 && tls.handshake.extension.type==65037", 1,
     "corrected field name; extensions_type is invalid in Wireshark 4.x"),

    ("2", "Hostname exposed, no ECH", "module2_tls_dns.pcap",
     "tls.handshake.type==1 && tls.handshake.extensions_server_name && "
     "!(tls.handshake.extension.type==65037)", 3,
     "the actual leak condition"),

    ("2", "Plaintext DNS query", "module2_tls_dns.pcap",
     "dns.flags.response==0", 3,
     "cleartext name resolution on UDP/53"),

    ("3", "Credentials in plaintext POST", "module3_http_tls.pcap",
     'http.request.method=="POST" && http contains "password"', 1,
     "form-encoded login body"),

    ("3", "HTTP Basic Authentication", "module3_http_tls.pcap",
     "http.authorization", 1,
     "base64 credentials in header"),

    ("3", "Benign HTTP not flagged", "module3_http_tls.pcap",
     'http.request.method=="GET" && !http.authorization && '
     '!(http contains "password")', 1,
     "control: ordinary GET must not match"),

    ("3", "Obsolete TLS version", "module3_http_tls.pcap",
     "tls.handshake.version==0x0300 || tls.handshake.version==0x0301", 1,
     "TLS 1.0 ClientHello"),

    ("3", "Weak cipher suite offered", "module3_http_tls.pcap",
     "tls.handshake.ciphersuite in {0x0001, 0x0004, 0x0005, 0x0009}", 1,
     "RC4 / single-DES / NULL; set syntax requires commas"),

    ("3", "Modern TLS not flagged", "module3_http_tls.pcap",
     "tls.handshake.type==1 && "
     "!(tls.handshake.ciphersuite in {0x0001, 0x0004, 0x0005, 0x0009}) && "
     "!(tls.handshake.version==0x0300 || tls.handshake.version==0x0301)", 1,
     "control: TLS 1.3 suites must not match"),
]


def run_filter(pcap, dfilter):
    """Returns (match_count, error_or_None)."""
    proc = subprocess.run(
        ["tshark", "-r", f"{TB}/{pcap}", "-Y", dfilter],
        capture_output=True, text=True
    )
    if "Constant expression is invalid" in proc.stderr or \
       "was unexpected" in proc.stderr or "syntax error" in proc.stderr.lower():
        return None, proc.stderr.strip().splitlines()[-1]
    lines = [l for l in proc.stdout.strip().splitlines() if l.strip()]
    return len(lines), None


def main():
    rows = []
    passed = failed = 0
    for mod, finding, pcap, dfilter, expected, note in TESTS:
        count, err = run_filter(pcap, dfilter)
        if err:
            status = "ERROR"
            failed += 1
            count_str = "invalid"
        else:
            status = "PASS" if count == expected else "FAIL"
            count_str = str(count)
            if status == "PASS":
                passed += 1
            else:
                failed += 1
        rows.append({
            "module": mod, "finding": finding, "filter": dfilter,
            "expected": expected, "observed": count_str,
            "status": status, "note": note,
        })
        print(f"[{status:5s}] M{mod} {finding:38s} expected={expected} observed={count_str}")

    print(f"\n{passed}/{len(TESTS)} filters verified, {failed} failed")

    with open(f"{TB}/filter_verification.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"Wrote {TB}/filter_verification.csv")


if __name__ == "__main__":
    main()
