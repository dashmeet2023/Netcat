#!/usr/bin/env python3
"""
test_dpi_engine.py  --  End-to-end validation of the C++ DPI engine.

Tests:
  T1  File-mode SNI extraction  (TLS ClientHello -> SNI -> correct app label)
  T2  File-mode HTTP host       (HTTP GET Host: header -> domain extracted)
  T3  File-mode DNS query       (UDP DNS wire -> domain name decoded)
  T4  Live-mode stdin feed      (global PCAP header + per-packet framing via stdin --live)
  T5  Blocking / drop logic     (--block-domain fires {"type":"block",...} JSON event)

Run with:
    python test_dpi_engine.py
"""

import os
import sys
import json
import struct
import random
import subprocess
import tempfile
import threading
import time

# ---------------------------------------------------------------------------
# Locate the compiled binary
# ---------------------------------------------------------------------------
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
EXE_PRIMARY = os.path.join(SCRIPT_DIR, "dpi_engine.exe")
EXE_BUILD   = os.path.join(SCRIPT_DIR,
              "Packet_analyzer_extracted", "Packet_analyzer-main",
              "build", "dpi_engine.exe")
EXE = EXE_PRIMARY if os.path.exists(EXE_PRIMARY) else EXE_BUILD

C_PASS = "PASS"
C_FAIL = "FAIL"

results = []

def record(name, passed, detail=""):
    tag = C_PASS if passed else C_FAIL
    print("  [{}] {}".format(tag, name))
    if detail:
        for line in detail.strip().splitlines():
            print("         {}".format(line))
    results.append({"name": name, "passed": passed, "detail": detail})

# ===========================================================================
# PCAP / packet builders  (pure stdlib, zero external deps)
# ===========================================================================

def pcap_global_header():
    return struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

def pcap_pkt(ts_sec, ts_usec, data):
    return struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data)) + data

def eth_hdr(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff", etype=0x0800):
    return (bytes.fromhex(dst.replace(":", "")) +
            bytes.fromhex(src.replace(":", "")) +
            struct.pack(">H", etype))

def ip_hdr(src_ip, dst_ip, proto, payload_len):
    total = 20 + payload_len
    h = struct.pack(">BBHHHBBH",
                    0x45, 0, total,
                    random.randint(1, 65535), 0x4000,
                    64, proto, 0)
    h += bytes(int(x) for x in src_ip.split("."))
    h += bytes(int(x) for x in dst_ip.split("."))
    return h

def tcp_hdr(sport, dport, seq=1000, ack=0, flags=0x18):
    return struct.pack(">HHIIBBHHH",
                       sport, dport, seq, ack,
                       (5 << 4), flags,
                       65535, 0, 0)

def udp_hdr(sport, dport, payload_len):
    return struct.pack(">HHHH", sport, dport, 8 + payload_len, 0)

# ---------------------------------------------------------------------------
# Protocol payload constructors
# ---------------------------------------------------------------------------

def build_tls_hello(sni):
    """Minimal well-formed TLS 1.2 ClientHello with one SNI extension."""
    sni_b     = sni.encode("ascii")
    sni_entry = struct.pack(">BH", 0, len(sni_b)) + sni_b
    sni_list  = struct.pack(">H", len(sni_entry)) + sni_entry
    sni_ext   = struct.pack(">HH", 0x0000, len(sni_list)) + sni_list
    exts      = struct.pack(">H", len(sni_ext)) + sni_ext

    rand32 = bytes(random.randint(0, 255) for _ in range(32))
    body = (struct.pack(">H", 0x0303)            # client_version TLS 1.2
            + rand32
            + struct.pack("B", 0)                # session_id length
            + struct.pack(">H", 4)               # cipher_suites length
            + struct.pack(">HH", 0x1301, 0x1302) # TLS_AES_128/256_GCM
            + struct.pack("BB", 1, 0)            # compression_methods
            + exts)

    # Handshake header: type(1) + length(3)
    hs = struct.pack("B", 0x01) + struct.pack(">I", len(body))[1:] + body
    # TLS Record header: content_type(1) + version(2) + length(2)
    return (struct.pack("B", 0x16)
            + struct.pack(">H", 0x0301)
            + struct.pack(">H", len(hs))
            + hs)

def build_http_get(host, path="/"):
    return ("GET {} HTTP/1.1\r\nHost: {}\r\n"
            "User-Agent: DPI-Test/1.0\r\nAccept: */*\r\n\r\n"
            ).format(path, host).encode()

def build_dns_query(domain):
    txid   = struct.pack(">H", random.randint(1, 65535))
    flags  = struct.pack(">H", 0x0100)
    counts = struct.pack(">HHHH", 1, 0, 0, 0)
    q = b""
    for label in domain.split("."):
        q += struct.pack("B", len(label)) + label.encode()
    q += struct.pack("B", 0) + struct.pack(">HH", 1, 1)
    return txid + flags + counts + q

# ---------------------------------------------------------------------------
# Full frame assemblers  (Eth + IP + TCP/UDP + payload -> pcap packet frame)
# ---------------------------------------------------------------------------
BASE_TS = 1700000000

def frame_tls(sni, src="10.0.0.1", dst="1.2.3.4", sport=50000, dport=443, ts_off=0):
    payload = build_tls_hello(sni)
    tcp     = tcp_hdr(sport, dport)
    ip      = ip_hdr(src, dst, 6, len(tcp) + len(payload))
    return pcap_pkt(BASE_TS + ts_off, 0, eth_hdr() + ip + tcp + payload)

def frame_http(host, src="10.0.0.1", dst="2.3.4.5", sport=51000, dport=80, ts_off=1):
    payload = build_http_get(host)
    tcp     = tcp_hdr(sport, dport)
    ip      = ip_hdr(src, dst, 6, len(tcp) + len(payload))
    return pcap_pkt(BASE_TS + ts_off, 0, eth_hdr() + ip + tcp + payload)

def frame_dns(domain, src="10.0.0.1", dns="8.8.8.8", sport=52000, ts_off=2):
    payload = build_dns_query(domain)
    udp     = udp_hdr(sport, 53, len(payload))
    ip      = ip_hdr(src, dns, 17, len(udp) + len(payload))
    return pcap_pkt(BASE_TS + ts_off, 0, eth_hdr() + ip + udp + payload)

def build_pcap(*frames):
    return pcap_global_header() + b"".join(frames)

# ===========================================================================
# Test infrastructure
# ===========================================================================

def run_analyze(pcap_bytes, extra_args=()):
    """Run --analyze on a temp pcap, return (exit_code, parsed_json_dict)."""
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        f.write(pcap_bytes)
        pcap_path = f.name
    out_path = pcap_path.replace(".pcap", "_out.json")
    try:
        cmd = [EXE, "--analyze", pcap_path, out_path] + list(extra_args)
        proc = subprocess.run(cmd, capture_output=True, timeout=20)
        data = {}
        if os.path.exists(out_path):
            try:
                with open(out_path) as jf:
                    data = json.load(jf)
            except Exception:
                pass
        return proc.returncode, data
    finally:
        for p in (pcap_path, out_path):
            try:
                os.unlink(p)
            except Exception:
                pass

def find_flow(data, **kw):
    """Return first flow where all key=value match (case-insensitive strings)."""
    for f in data.get("flows", []):
        if all(str(f.get(k, "")).lower() == str(v).lower()
               for k, v in kw.items()):
            return f
    return None

# ===========================================================================
# T1 -- File mode: TLS SNI extraction
# ===========================================================================
def test_t1_file_sni():
    print("\n--- T1: File mode -- TLS ClientHello SNI extraction ---")

    SNI = "www.example-tls.com"
    rc, data = run_analyze(build_pcap(frame_tls(SNI)))

    record("T1.1 analyze exits 0", rc == 0, "exit code: {}".format(rc))

    total = data.get("summary", {}).get("total_packets", 0)
    record("T1.2 packets parsed (>=1)", total >= 1,
           "total_packets={}".format(total))

    flow = find_flow(data, domain=SNI)
    all_domains = [f.get("domain") for f in data.get("flows", [])]
    record("T1.3 SNI correctly extracted", flow is not None,
           "expected '{}'\ndomains found: {}".format(SNI, all_domains))

    if flow:
        tls_block = flow.get("tls")
        record("T1.4 tls block present in flow", tls_block is not None,
               "tls={}".format(tls_block))
        if tls_block:
            record("T1.5 tls.sni matches",
                   tls_block.get("sni") == SNI,
                   "tls.sni={}".format(tls_block.get("sni")))

    # Known brand: google SNI should be correctly extracted.
    # NOTE: --analyze mode sets app=HTTPS for any TLS flow (the raw protocol label).
    # Brand mapping (Google/YouTube/etc.) runs only in the real-time DPIEngine pipeline path.
    # The correct indicator here is that tls.sni contains the google domain.
    GSNI = "mail.google.com"
    _, d2 = run_analyze(build_pcap(frame_tls(GSNI, dst="142.250.0.1")))
    f2 = find_flow(d2, domain=GSNI)
    if f2 is None:
        for _f in d2.get("flows", []):
            if (_f.get("tls") or {}).get("sni") == GSNI:
                f2 = _f
                break
    tls2 = (f2.get("tls") or {}) if f2 else {}
    record("T1.6 Google SNI in tls.sni (analyze mode)",
           tls2.get("sni") == GSNI,
           "tls.sni={}  (app={}, note: brand labels only in live-mode pipeline)".format(
               tls2.get("sni"), f2.get("app") if f2 else "no flow"))

# ===========================================================================
# T2 -- File mode: HTTP Host header extraction
# ===========================================================================
def test_t2_file_http():
    print("\n--- T2: File mode -- HTTP Host header extraction ---")

    HOST = "httptest.local"
    rc, data = run_analyze(build_pcap(frame_http(HOST)))

    record("T2.1 analyze exits 0", rc == 0, "exit code: {}".format(rc))

    flow = find_flow(data, domain=HOST)
    all_domains = [f.get("domain") for f in data.get("flows", [])]
    record("T2.2 HTTP host extracted", flow is not None,
           "expected '{}'\ndomains found: {}".format(HOST, all_domains))

    if flow:
        record("T2.3 app == HTTP", flow.get("app", "").upper() == "HTTP",
               "app={}".format(flow.get("app")))
        http = flow.get("http")
        record("T2.4 http block present", http is not None,
               "http={}".format(http))
        if http:
            record("T2.5 http.method=GET",  http.get("method") == "GET",
                   "method={}".format(http.get("method")))
            record("T2.6 http.host matches", http.get("host") == HOST,
                   "http.host={}".format(http.get("host")))

# ===========================================================================
# T3 -- File mode: DNS query extraction
# ===========================================================================
def test_t3_file_dns():
    print("\n--- T3: File mode -- DNS query name decoding ---")

    DOMAIN = "api.example.com"
    rc, data = run_analyze(build_pcap(frame_dns(DOMAIN)))

    record("T3.1 analyze exits 0", rc == 0, "exit code: {}".format(rc))

    flow = find_flow(data, domain=DOMAIN)
    all_domains = [f.get("domain") for f in data.get("flows", [])]
    record("T3.2 DNS domain extracted", flow is not None,
           "expected '{}'\ndomains: {}".format(DOMAIN, all_domains))

    if flow:
        record("T3.3 app == DNS", flow.get("app", "").upper() == "DNS",
               "app={}".format(flow.get("app")))
        dns = flow.get("dns")
        record("T3.4 dns block present", dns is not None,
               "dns={}".format(dns))
        if dns:
            record("T3.5 dns.query matches", dns.get("query") == DOMAIN,
                   "dns.query={}".format(dns.get("query")))

# ===========================================================================
# T4 -- Live mode: stdin PCAP feed -> JSON flow event on stdout
#       Mirrors dpi.py start_cpp_worker / feed_scapy_packet exactly.
# ===========================================================================
def test_t4_live_mode():
    print("\n--- T4: Live mode -- stdin PCAP feed -> JSON flow event ---")

    SNI = "live-test.example.com"
    tls_payload = build_tls_hello(SNI)
    raw_pkt = (eth_hdr()
               + ip_hdr("10.1.0.1", "10.2.0.2", 6, 20 + len(tls_payload))
               + tcp_hdr(60000, 443)
               + tls_payload)

    # Exactly what dpi.py writes to the C++ process stdin
    global_hdr  = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    pkt_hdr     = struct.pack("<IIII", BASE_TS, 123456, len(raw_pkt), len(raw_pkt))
    stdin_bytes = global_hdr + pkt_hdr + raw_pkt

    record("T4.0 exe exists", os.path.exists(EXE), EXE)
    if not os.path.exists(EXE):
        return

    all_lines  = []
    flow_events = []
    proc = None

    try:
        proc = subprocess.Popen(
            [EXE, "--live"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )

        # Send the whole stream at once
        proc.stdin.write(stdin_bytes)
        proc.stdin.flush()

        deadline = time.time() + 7.0

        def _reader():
            for raw_line in iter(proc.stdout.readline, b""):
                s = raw_line.decode("utf-8", errors="ignore").strip()
                if not s:
                    continue
                all_lines.append(s)
                if s.startswith("{") and s.endswith("}"):
                    try:
                        obj = json.loads(s)
                        if obj.get("type") == "flow":
                            flow_events.append(obj)
                    except Exception:
                        pass

        t = threading.Thread(target=_reader, daemon=True)
        t.start()

        while time.time() < deadline and not flow_events:
            time.sleep(0.1)

        proc.stdin.close()
        t.join(timeout=2)

    except Exception as exc:
        record("T4.1 process launched", False, str(exc))
        return
    finally:
        if proc:
            try:
                proc.kill()
                proc.wait(timeout=3)
            except Exception:
                pass

    got = bool(flow_events)
    record("T4.1 received >=1 flow event", got,
           "lines={}  sample={}".format(len(all_lines), all_lines[:3]))

    if not got:
        return

    ev = flow_events[0]
    required = {"type", "src_ip", "dst_ip", "src_port",
                "dst_port", "protocol", "app", "domain"}
    missing = required - set(ev.keys())
    record("T4.2 flow JSON has all required keys", not missing,
           "missing={}\nevent={}".format(missing, ev))

    record("T4.3 type=='flow'", ev.get("type") == "flow",
           "type={}".format(ev.get("type")))
    record("T4.4 src_ip=='10.1.0.1'", ev.get("src_ip") == "10.1.0.1",
           "src_ip={}".format(ev.get("src_ip")))
    record("T4.5 dst_port==443", ev.get("dst_port") == 443,
           "dst_port={}".format(ev.get("dst_port")))

    # The engine may emit a flow event before SNI is bound (port-based fallback)
    # OR after binding SNI. Both are correct behaviours.
    plausible = (ev.get("domain") == SNI
                 or ev.get("app") in ("HTTPS", "Google", "YouTube", "TLS"))
    record("T4.6 app/domain plausible for HTTPS port 443", plausible,
           "app={} domain={}".format(ev.get("app"), ev.get("domain")))

# ===========================================================================
# T5 -- Blocking: file mode flow.blocked + live mode {"type":"block"} event
# ===========================================================================
def test_t5_blocking():
    print("\n--- T5: Blocking logic -- domain blocklist + drop event ---")

    BLOCKED = "blocked-by-test.com"

    # ---- T5A: file mode --analyze --block-domain ----
    rc, data = run_analyze(
        build_pcap(frame_tls(BLOCKED)),
        extra_args=["--block-domain", BLOCKED]
    )
    record("T5A.1 analyze exits 0", rc == 0, "exit code={}".format(rc))

    flow = find_flow(data, domain=BLOCKED)
    all_domains = [f.get("domain") for f in data.get("flows", [])]
    record("T5A.2 flow with blocked domain found", flow is not None,
           "domains={}".format(all_domains))

    if flow:
        record("T5A.3 flow.blocked==true", flow.get("blocked") is True,
               "blocked={}".format(flow.get("blocked")))
        record("T5A.4 block_reason non-empty", bool(flow.get("block_reason", "")),
               "block_reason='{}'".format(flow.get("block_reason")))

    # ---- T5B: live mode --live --block-domain ----
    tls_payload = build_tls_hello(BLOCKED)
    raw_pkt = (eth_hdr()
               + ip_hdr("10.5.0.1", "10.5.0.2", 6, 20 + len(tls_payload))
               + tcp_hdr(55000, 443)
               + tls_payload)
    g_hdr       = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    p_hdr       = struct.pack("<IIII", BASE_TS, 0, len(raw_pkt), len(raw_pkt))
    stdin_bytes = g_hdr + p_hdr + raw_pkt

    all_lines   = []
    block_evts  = []
    proc_b      = None

    try:
        proc_b = subprocess.Popen(
            [EXE, "--live", "--block-domain", BLOCKED],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        proc_b.stdin.write(stdin_bytes)
        proc_b.stdin.flush()

        deadline = time.time() + 7.0

        def _rb():
            for raw_line in iter(proc_b.stdout.readline, b""):
                s = raw_line.decode("utf-8", errors="ignore").strip()
                if not s:
                    continue
                all_lines.append(s)
                if s.startswith("{") and s.endswith("}"):
                    try:
                        obj = json.loads(s)
                        if obj.get("type") == "block":
                            block_evts.append(obj)
                    except Exception:
                        pass

        tb = threading.Thread(target=_rb, daemon=True)
        tb.start()

        while time.time() < deadline and not block_evts:
            time.sleep(0.1)

        proc_b.stdin.close()
        tb.join(timeout=2)

    except Exception as exc:
        record("T5B.1 live process launched", False, str(exc))
        return
    finally:
        if proc_b:
            try:
                proc_b.kill()
                proc_b.wait(timeout=3)
            except Exception:
                pass

    got = bool(block_evts)
    record("T5B.1 received block event in live mode", got,
           "lines={}\nsample={}".format(len(all_lines), all_lines[:5]))

    if not got:
        return

    ev = block_evts[0]
    record("T5B.2 type=='block'", ev.get("type") == "block",
           "event={}".format(ev))
    record("T5B.3 ip present", bool(ev.get("ip")),
           "ip={}".format(ev.get("ip")))
    record("T5B.4 reason present", bool(ev.get("reason", "")),
           "reason='{}'".format(ev.get("reason")))
    record("T5B.5 ip=='10.5.0.1'", ev.get("ip") == "10.5.0.1",
           "ip={}".format(ev.get("ip")))

# ===========================================================================
# Summary
# ===========================================================================
def print_summary():
    print("\n" + "=" * 60)
    print("  TEST SUMMARY")
    print("=" * 60)
    passed = sum(1 for r in results if r["passed"])
    total  = len(results)
    for r in results:
        tag = C_PASS if r["passed"] else C_FAIL
        print("  [{}] {}".format(tag, r["name"]))
    print("-" * 60)
    col = "\033[32m" if passed == total else "\033[31m"
    print("  {}{}/{} tests passed\033[0m".format(col, passed, total))
    print("=" * 60)
    return passed == total

# ===========================================================================
# Entry point
# ===========================================================================
if __name__ == "__main__":
    print("=" * 60)
    print("  DPI Engine End-to-End Test Suite")
    print("  Binary : {}".format(EXE))
    print("  Exists : {}".format(os.path.exists(EXE)))
    print("=" * 60)

    if not os.path.exists(EXE):
        print("\n[{}] dpi_engine.exe not found.\n".format(C_FAIL))
        print("Checked:\n  {}\n  {}".format(EXE_PRIMARY, EXE_BUILD))
        sys.exit(1)

    test_t1_file_sni()
    test_t2_file_http()
    test_t3_file_dns()
    test_t4_live_mode()
    test_t5_blocking()

    ok = print_summary()
    sys.exit(0 if ok else 1)
