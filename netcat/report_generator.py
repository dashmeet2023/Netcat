import os
import json
import subprocess
import time
import logging
import threading
from fpdf import FPDF
from netcat.database import DatabaseManager

class ForensicPDF(FPDF):
    def header(self):
        # Dark Blue header strip
        self.set_fill_color(26, 54, 93) # Dark Navy Blue
        self.rect(0, 0, 210, 25, 'F')
        
        self.set_font('helvetica', 'B', 15)
        self.set_text_color(255, 255, 255)
        self.set_y(8)
        self.cell(0, 10, 'NETCAT INCIDENT FORENSIC REPORT', border=False, align='C')
        self.ln(15)
        
    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}} | Confidential', align='C')

class ReportGenerator:
    _lock = threading.Lock()
    _cooldowns = {} # (ip, rule) -> last report time
    db_manager = None

    @classmethod
    def generate_report(cls, alert_id, event, pcap_path):
        """
        Main entrypoint. Generates JSON, MD, and PDF reports.
        """
        ip = event.src_ip
        rule = event.rule
        
        # Enforce rate-limit cooldown (5 seconds matching alert cooldown)
        with cls._lock:
            now = time.time()
            cooldown_key = (ip, rule)
            if cooldown_key in cls._cooldowns:
                if now - cls._cooldowns[cooldown_key] < 5.0:
                    logging.info(f"Report for {cooldown_key} skipped due to cooldown")
                    return
            cls._cooldowns[cooldown_key] = now

        try:
            workspace_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            exe_path = os.path.join(workspace_dir, "dpi_engine.exe")
            reports_dir = os.path.join(workspace_dir, "reports")
            os.makedirs(reports_dir, exist_ok=True)
            
            json_data = None
            
            # 1. Try C++ DPI Analyze mode
            if os.path.exists(exe_path):
                temp_json_path = os.path.join(reports_dir, f"temp_{alert_id}.json")
                try:
                    logging.info(f"[REPORT:{alert_id}] C++ DPI Analyze mode: running {exe_path} --analyze {pcap_path}")
                    # Augment PATH with common MinGW64 DLL locations so dpi_engine.exe
                    # finds its runtime DLLs (libstdc++-6.dll, libgcc_s_seh-1.dll etc.)
                    # even when the parent process was launched without MinGW on PATH.
                    _run_env = os.environ.copy()
                    _mingw_dirs = [
                        r"C:\msys64\mingw64\bin",
                        r"C:\msys64\ucrt64\bin",
                        r"C:\mingw64\bin",
                        r"C:\MinGW\bin",
                    ]
                    _extra = os.pathsep.join(d for d in _mingw_dirs if os.path.isdir(d))
                    if _extra:
                        _run_env["PATH"] = _extra + os.pathsep + _run_env.get("PATH", "")
                    proc = subprocess.run(
                        [exe_path, "--analyze", pcap_path, temp_json_path],
                        capture_output=True,
                        text=True,
                        timeout=5.0,
                        env=_run_env,
                    )
                    if proc.returncode == 0 and os.path.exists(temp_json_path):
                        with open(temp_json_path, 'r', encoding='utf-8') as f:
                            json_data = json.load(f)
                        os.remove(temp_json_path)
                        logging.info(f"[REPORT:{alert_id}] C++ DPI Analyze mode succeeded.")
                    else:
                        stderr_snippet = (proc.stderr or "").strip()[:300]
                        logging.warning(
                            f"[REPORT:{alert_id}] C++ DPI Analyze mode failed (exit={proc.returncode}). "
                            f"stderr: {stderr_snippet or '(empty)'}. Falling back to Python parser."
                        )
                except Exception as cpp_ex:
                    logging.warning(f"[REPORT:{alert_id}] C++ DPI Analyzer execution error: {cpp_ex}. Falling back to Python parser.")
            
            # 2. Python parsing Fallback if C++ is not available or failed
            if json_data is None:
                logging.info(f"[REPORT:{alert_id}] Python fallback parser engaged (C++ not available or failed).")
                json_data = cls.analyze_pcap_python(pcap_path, event)

                
            # 3. Save JSON analysis to Database
            db = cls.db_manager or DatabaseManager()
            db.log_threat_analysis(alert_id, json.dumps(json_data))
            
            # 4. Generate Markdown report
            md_path = os.path.join(reports_dir, f"{alert_id}.md")
            cls.write_markdown_report(md_path, alert_id, event, json_data)
            
            # 5. Generate PDF report
            pdf_path = os.path.join(reports_dir, f"{alert_id}.pdf")
            cls.write_pdf_report(pdf_path, alert_id, event, json_data)
            
            logging.info(f"Successfully generated forensic reports for Alert {alert_id} inside {reports_dir}")
            
        except Exception as e:
            logging.error(f"Failed to generate forensic report: {e}", exc_info=True)

    @classmethod
    def analyze_pcap_python(cls, pcap_path, event):
        """
        Pure-Python fallback. Parses PCAP using Scapy and returns matching JSON schema.
        """
        from scapy.all import rdpcap, IP, IPv6, TCP, UDP, Raw
        
        try:
            packets = rdpcap(pcap_path)
        except Exception as e:
            return {"error": f"Failed to parse pcap: {e}"}
            
        total_packets = 0
        total_bytes = 0
        start_time = 0.0
        end_time = 0.0
        tcp_packets = 0
        udp_packets = 0
        
        flow_records = {}
        packet_records = []
        
        for idx, pkt in enumerate(packets):
            if not pkt.haslayer(IP) and not pkt.haslayer(IPv6):
                continue
            if not pkt.haslayer(TCP) and not pkt.haslayer(UDP):
                continue
                
            ts = float(pkt.time) if pkt.time else time.time()
            if total_packets == 0:
                start_time = ts
            end_time = ts
            total_packets += 1
            
            pkt_len = len(pkt)
            total_bytes += pkt_len
            
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                protocol_num = pkt[IP].proto
            else:
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst
                protocol_num = pkt[IPv6].nh
                
            proto = "TCP" if pkt.haslayer(TCP) else "UDP"
            if proto == "TCP":
                tcp_packets += 1
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                flags = int(pkt[TCP].flags)
                seq = pkt[TCP].seq
                ack = pkt[TCP].ack
                window = pkt[TCP].window
            else:
                udp_packets += 1
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                flags = 0
                seq = 0
                ack = 0
                window = 0
                
            payload = b""
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
            elif proto == "TCP" and len(pkt[TCP].payload) > 0:
                payload = bytes(pkt[TCP].payload)
            elif proto == "UDP" and len(pkt[UDP].payload) > 0:
                payload = bytes(pkt[UDP].payload)
                
            payload_len = len(payload)
            
            # Truncated payload preview
            display_limit = 32
            display_len = min(payload_len, display_limit)
            if payload_len == 0:
                payload_preview = "No payload"
            else:
                hex_str = " ".join(f"{b:02x}" for b in payload[:display_len])
                if payload_len > display_limit:
                    hex_str += " ..."
                ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in payload[:display_len])
                if payload_len > display_limit:
                    ascii_str += " ..."
                payload_preview = f"Hex: {hex_str} | ASCII: {ascii_str}"
                
            is_tls = False
            tls_version = ""
            cipher_suites = []
            sni = ""
            app = "Unknown"
            
            from netcat.dpi import DPIEngine
            if proto == "TCP" and payload_len > 0:
                extracted_sni = DPIEngine.extract_tls_sni(payload)
                if extracted_sni:
                    is_tls = True
                    sni = extracted_sni
                    app = "HTTPS"
                    if payload_len >= 5:
                        rec_version = (payload[1] << 8) | payload[2]
                        if rec_version == 0x0301: tls_version = "TLS 1.0"
                        elif rec_version == 0x0302: tls_version = "TLS 1.1"
                        elif rec_version == 0x0303: tls_version = "TLS 1.2"
                        elif rec_version == 0x0304: tls_version = "TLS 1.3"
                        else: tls_version = f"0x{rec_version:04x}"
                        
                        # Cipher suites parsing
                        try:
                            if payload_len >= 43:
                                offset = 5
                                offset += 4 # handshake header
                                offset += 2 # client version
                                offset += 32 # random
                                session_id_len = payload[offset]
                                offset += 1 + session_id_len
                                cipher_len = (payload[offset] << 8) | payload[offset+1]
                                offset += 2
                                for c_idx in range(0, cipher_len, 2):
                                    if offset + c_idx + 1 < payload_len:
                                        suite = (payload[offset + c_idx] << 8) | payload[offset + c_idx + 1]
                                        cipher_suites.append(f"0x{suite:04x}")
                        except Exception:
                            pass
                elif DPIEngine.is_http_request(payload):
                    extracted_host = DPIEngine.extract_http_host(payload)
                    if extracted_host:
                        sni = extracted_host
                        app = "HTTP"
            elif proto == "UDP" and payload_len > 0:
                dns_query = DPIEngine.extract_dns_query(payload)
                if dns_query:
                    sni = dns_query
                    app = "DNS"
                    
            if app == "Unknown":
                if dst_port == 443 or src_port == 443:
                    app = "HTTPS"
                elif dst_port == 80 or src_port == 80:
                    app = "HTTP"
                elif dst_port == 53 or src_port == 53:
                    app = "DNS"
                    
            key = (src_ip, dst_ip, protocol_num, src_port, dst_port)
            if key not in flow_records:
                flow_records[key] = {
                    "flow_id": f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} ({proto})",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": proto,
                    "app": app,
                    "domain": sni,
                    "blocked": False,
                    "block_reason": "",
                    "packet_count": 0,
                    "byte_count": 0,
                    "duration_sec": 0.0,
                    "start_ts": ts,
                    "end_ts": ts,
                    "is_tls": is_tls,
                    "tls_version": tls_version,
                    "cipher_suites": cipher_suites,
                    "is_http": False,
                    "http_method": "",
                    "http_path": "",
                    "http_host": "",
                    "is_dns": False,
                    "dns_query": "",
                    "timeline": []
                }
                
                if app == "HTTP" and payload_len > 0:
                    flow_records[key]["is_http"] = True
                    try:
                        lines = payload.decode('utf-8', errors='ignore').split('\r\n')
                        if lines:
                            parts = lines[0].split(' ')
                            if len(parts) >= 2:
                                flow_records[key]["http_method"] = parts[0]
                                flow_records[key]["http_path"] = parts[1]
                            for line in lines:
                                if line.lower().startswith("host:"):
                                    flow_records[key]["http_host"] = line.split(":", 1)[1].strip()
                    except Exception:
                        pass
                elif app == "DNS":
                    flow_records[key]["is_dns"] = True
                    flow_records[key]["dns_query"] = sni
                    
            flow = flow_records[key]
            flow["packet_count"] += 1
            flow["byte_count"] += pkt_len
            flow["end_ts"] = ts
            flow["duration_sec"] = ts - flow["start_ts"]
            if sni and not flow["domain"]:
                flow["domain"] = sni
                if app != "Unknown":
                    flow["app"] = app
                    
            info = f"{proto} ["
            if proto == "TCP":
                flag_list = []
                if flags & 0x02: flag_list.append("SYN")
                if flags & 0x10: flag_list.append("ACK")
                if flags & 0x01: flag_list.append("FIN")
                if flags & 0x04: flag_list.append("RST")
                if flags & 0x08: flag_list.append("PSH")
                info += ",".join(flag_list)
                info += f"] Seq={seq}"
            else:
                info += "UDP]"
                
            gap_ms = 0.0
            if flow["timeline"]:
                gap_ms = (ts - flow["timeline"][-1]["ts"]) * 1000.0
                
            flow["timeline"].append({
                "packet_idx": idx,
                "ts": ts,
                "gap_ms": gap_ms,
                "info": info
            })
            
            packet_records.append({
                "idx": idx,
                "ts": ts,
                "src": f"{src_ip}:{src_port}",
                "dst": f"{dst_ip}:{dst_port}",
                "proto": proto,
                "length": pkt_len,
                "info": info,
                "payload_preview": payload_preview
            })
            
        duration = end_time - start_time if total_packets > 0 else 0.0
        
        json_data = {
            "summary": {
                "total_packets": total_packets,
                "total_bytes": total_bytes,
                "duration_sec": duration,
                "tcp_packets": tcp_packets,
                "udp_packets": udp_packets
            },
            "flows": [],
            "packets": packet_records
        }
        
        for key, f in flow_records.items():
            flow_item = {
                "flow_id": f["flow_id"],
                "src_ip": f["src_ip"],
                "dst_ip": f["dst_ip"],
                "src_port": f["src_port"],
                "dst_port": f["dst_port"],
                "protocol": f["protocol"],
                "app": f["app"],
                "domain": f["domain"],
                "blocked": False,
                "block_reason": "",
                "packet_count": f["packet_count"],
                "byte_count": f["byte_count"],
                "duration_sec": f["duration_sec"],
                "tls": {
                    "version": f["tls_version"],
                    "sni": f["domain"],
                    "cipher_suites": f["cipher_suites"]
                } if f["is_tls"] else None,
                "http": {
                    "method": f["http_method"],
                    "path": f["http_path"],
                    "host": f["http_host"]
                } if f["is_http"] else None,
                "dns": {
                    "query": f["dns_query"]
                } if f["is_dns"] else None,
                "timeline": f["timeline"]
            }
            json_data["flows"].append(flow_item)
            
        return json_data

    @classmethod
    def write_markdown_report(cls, path, alert_id, event, data):
        """
        Creates a clean Markdown report detailing the forensic metrics.
        """
        summary = data.get("summary", {})
        
        md = f"""# NETCAT Forensic Analysis Report (Alert ID: {alert_id})

## Metadata
* **Timestamp**: {event.timestamp}
* **Source IP**: {event.src_ip}
* **Triggered Rule**: {event.rule}
* **Severity**: {event.severity}
* **Description/Detail**: {event.detail}

## Session Capture Stats
* **Total Captured Packets**: {summary.get("total_packets", 0)}
* **Total Captured Bytes**: {summary.get("total_bytes", 0)} bytes
* **Capture Duration**: {summary.get("duration_sec", 0.0):.3f} seconds
* **TCP Count**: {summary.get("tcp_packets", 0)}
* **UDP Count**: {summary.get("udp_packets", 0)}

## Flow Reconstructions
"""
        for idx, flow in enumerate(data.get("flows", [])):
            md += f"""
### Flow {idx + 1}: {flow.get("flow_id")}
* **Application**: {flow.get("app")}
* **Associated Domain**: {flow.get("domain", "N/A")}
* **Packet Count**: {flow.get("packet_count")} packets
* **Total Bytes**: {flow.get("byte_count")} bytes
* **Flow Duration**: {flow.get("duration_sec", 0.0):.3f} seconds
"""
            if flow.get("tls"):
                tls = flow["tls"]
                md += f"""* **TLS Details**:
    * **TLS Version**: {tls.get("version")}
    * **SNI**: {tls.get("sni")}
    * **Cipher Suites**: {", ".join(tls.get("cipher_suites", [])) or "None"}
"""
            if flow.get("http"):
                http = flow["http"]
                md += f"""* **HTTP Request Details**:
    * **Method**: {http.get("method")}
    * **Request Path**: `{http.get("path")}`
    * **Host Header**: {http.get("host")}
"""
            if flow.get("dns"):
                dns = flow["dns"]
                md += f"""* **DNS Details**:
    * **Queried Domain**: {dns.get("query")}
"""
            # Timeline sub-table
            md += "\n#### Packet Timeline\n"
            md += "| Packet | Offset (ms) | TCP/UDP Details |\n"
            md += "| --- | --- | --- |\n"
            for t_ev in flow.get("timeline", [])[:10]: # limit to first 10 for readability
                md += f"| #{t_ev.get('packet_idx')} | +{t_ev.get('gap_ms', 0.0):.2f} ms | {t_ev.get('info')} |\n"
            if len(flow.get("timeline", [])) > 10:
                md += f"| ... | ... | *({len(flow['timeline'])} total packets in flow)* |\n"
                
        # Raw Packet timeline previews
        md += "\n## Packet Previews (Truncated Payload)\n"
        md += "| Index | Timestamp | Src -> Dst | Length | Protocol/Info | Payload Preview |\n"
        md += "| --- | --- | --- | --- | --- | --- |\n"
        for pkt in data.get("packets", [])[:10]: # limit to first 10
            md += f"| #{pkt.get('idx')} | {pkt.get('ts'):.6f} | {pkt.get('src')} -> {pkt.get('dst')} | {pkt.get('length')} B | {pkt.get('proto')} | `{pkt.get('payload_preview')}` |\n"
            
        if len(data.get("packets", [])) > 10:
            md += f"\n*... showing first 10 of {len(data['packets'])} total packets. Full analysis log stored in SQLite.*"
            
        with open(path, 'w', encoding='utf-8') as f:
            f.write(md)

    @classmethod
    def write_pdf_report(cls, path, alert_id, event, data):
        """
        Builds a professionally styled PDF forensic document via fpdf2.
        """
        pdf = ForensicPDF()
        pdf.alias_nb_pages()
        pdf.add_page()
        
        # Colors definition
        primary_color = (26, 54, 93) # Dark Navy
        text_color = (45, 55, 72) # Slate Grey
        
        # Section title helper
        def draw_section_header(title):
            pdf.ln(5)
            pdf.set_fill_color(*primary_color)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font('helvetica', 'B', 11)
            pdf.cell(0, 7, f"  {title.upper()}", fill=True, new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)
            pdf.set_text_color(*text_color)
            
        # 1. Metadata Block
        draw_section_header("Incident Information")
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(40, 6, "Alert Reference:")
        pdf.set_font('helvetica', '', 9)
        pdf.cell(50, 6, f"Alert #{alert_id}")
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(40, 6, "Source IP Address:")
        pdf.set_font('helvetica', '', 9)
        pdf.cell(0, 6, f"{event.src_ip}", new_x="LMARGIN", new_y="NEXT")
        
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(40, 6, "Detected Threat:")
        pdf.set_font('helvetica', '', 9)
        pdf.cell(50, 6, f"{event.rule}")
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(40, 6, "Incident Severity:")
        pdf.set_font('helvetica', '', 9)
        pdf.cell(0, 6, f"{event.severity.upper()}", new_x="LMARGIN", new_y="NEXT")
        
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(40, 6, "Logged Timestamp:")
        pdf.set_font('helvetica', '', 9)
        pdf.cell(0, 6, f"{event.timestamp}", new_x="LMARGIN", new_y="NEXT")
        
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(40, 6, "Incident Details:")
        pdf.set_font('helvetica', '', 9)
        pdf.multi_cell(0, 6, f"{event.detail}")
        
        # 2. Capture Stats
        summary = data.get("summary", {})
        draw_section_header("Traffic Session Overview")
        
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(45, 6, "Captured Packets:")
        pdf.set_font('helvetica', '', 9)
        pdf.cell(45, 6, f"{summary.get('total_packets', 0)} packets")
        
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(45, 6, "Session Byte Count:")
        pdf.set_font('helvetica', '', 9)
        pdf.cell(0, 6, f"{summary.get('total_bytes', 0)} bytes", new_x="LMARGIN", new_y="NEXT")
        
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(45, 6, "Capture Duration:")
        pdf.set_font('helvetica', '', 9)
        pdf.cell(45, 6, f"{summary.get('duration_sec', 0.0):.4f} seconds")
        
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(45, 6, "Protocols:")
        pdf.set_font('helvetica', '', 9)
        pdf.cell(0, 6, f"TCP: {summary.get('tcp_packets', 0)} / UDP: {summary.get('udp_packets', 0)}", new_x="LMARGIN", new_y="NEXT")
        
        # 3. Flows Reconstruction
        draw_section_header("Flow Reconstruction & DPI Verdicts")
        for idx, flow in enumerate(data.get("flows", [])[:5]):
            pdf.set_font('helvetica', 'B', 9)
            pdf.cell(0, 6, f"Flow #{idx+1}: {flow.get('flow_id')}", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font('helvetica', '', 8)
            pdf.cell(40, 5, f"  Application: {flow.get('app')}")
            pdf.cell(60, 5, f"  Domain/Host: {flow.get('domain', 'N/A')}")
            pdf.cell(0, 5, f"  Duration: {flow.get('duration_sec', 0.0):.3f}s | Packets: {flow.get('packet_count')}", new_x="LMARGIN", new_y="NEXT")
            
            if flow.get("tls"):
                tls = flow["tls"]
                pdf.cell(0, 5, f"  [TLS Client Hello] Version: {tls.get('version')} | SNI: {tls.get('sni')}", new_x="LMARGIN", new_y="NEXT")
            if flow.get("http"):
                http = flow["http"]
                pdf.cell(0, 5, f"  [HTTP Request] Method: {http.get('method')} | Path: {http.get('path')}", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(1)
            
        # 4. Truncated Previews
        draw_section_header("Packet Payload Previews (Monospace Preview)")
        pdf.set_font('courier', '', 7)
        for pkt in data.get("packets", [])[:8]:
            line = f"#{pkt.get('idx')} [{pkt.get('proto')}]: {pkt.get('src')}->{pkt.get('dst')} | Len: {pkt.get('length')}B | {pkt.get('payload_preview')[:80]}"
            pdf.cell(0, 4, line, new_x="LMARGIN", new_y="NEXT")
            
        pdf.output(path)

    @classmethod
    def generate_combined_session_report(cls, threat_events):
        """
        Combines multiple incident reports into a single consolidated master report.
        """
        workspace_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        reports_dir = os.path.join(workspace_dir, "reports")
        os.makedirs(reports_dir, exist_ok=True)
        
        summary_md_path = os.path.join(reports_dir, "session_summary.md")
        summary_pdf_path = os.path.join(reports_dir, "session_summary.pdf")
        
        # 1. Master MD Report
        md = f"""# NETCAT Master Session Incident Summary Report

* **Generated On**: {time.strftime("%Y-%m-%d %H:%M:%S")}
* **Total Incident Events**: {len(threat_events)}

---

## Incidents Log Index
| Alert ID | Timestamp | Source IP | Threat Rule | Severity | Details |
| --- | --- | --- | --- | --- | --- |
"""
        for ev in threat_events:
            md += f"| Alert #{ev.alert_id} | {ev.timestamp} | {ev.src_ip} | {ev.rule} | {ev.severity.upper()} | {ev.detail} |\n"
            
        md += "\n\n## Individual Forensic Analyses\n"
        db = DatabaseManager()
        for ev in threat_events:
            md += f"\n---\n### Forensic Details: Alert #{ev.alert_id} ({ev.rule})\n"
            json_str = db.get_threat_analysis(ev.alert_id)
            if json_str:
                try:
                    js = json.loads(json_str)
                    sumry = js.get("summary", {})
                    md += f"""
* **Total Session Packets**: {sumry.get("total_packets", 0)}
* **Total Session Bytes**: {sumry.get("total_bytes", 0)} bytes
* **Capture Duration**: {sumry.get("duration_sec", 0.0):.3f}s
* **Traffic Flows Analyzed**:\n"""
                    for flw in js.get("flows", [])[:3]:
                        md += f"  * `{flw.get('flow_id')}` | App: **{flw.get('app')}** | SNI: `{flw.get('domain', 'N/A')}`\n"
                except Exception:
                    md += "*Failed to parse JSON blob analysis.*\n"
            else:
                md += "*Forensic deep-packet timeline pending or not generated.*\n"
                
        with open(summary_md_path, 'w', encoding='utf-8') as f:
            f.write(md)
            
        # 2. Master PDF Summary
        pdf = ForensicPDF()
        pdf.alias_nb_pages()
        pdf.add_page()
        
        pdf.set_fill_color(26, 54, 93)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font('helvetica', 'B', 12)
        pdf.cell(0, 8, "  CONSOLIDATED INCIDENT INDEX", fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)
        pdf.set_text_color(45, 55, 72)
        
        # Draw Index Table in PDF
        pdf.set_font('helvetica', 'B', 8)
        pdf.cell(15, 6, "ID", border=1)
        pdf.cell(35, 6, "Timestamp", border=1)
        pdf.cell(30, 6, "Source IP", border=1)
        pdf.cell(50, 6, "Threat Rule", border=1)
        pdf.cell(20, 6, "Severity", border=1)
        pdf.cell(0, 6, "Action", border=1, new_x="LMARGIN", new_y="NEXT")
        
        pdf.set_font('helvetica', '', 7)
        for ev in threat_events[:20]:
            pdf.cell(15, 5, f"#{ev.alert_id}", border=1)
            pdf.cell(35, 5, f"{ev.timestamp}", border=1)
            pdf.cell(30, 5, f"{ev.src_ip}", border=1)
            pdf.cell(50, 5, f"{ev.rule[:30]}", border=1)
            pdf.cell(20, 5, f"{ev.severity.upper()}", border=1)
            pdf.cell(0, 5, "Logged", border=1, new_x="LMARGIN", new_y="NEXT")
            
        pdf.output(summary_pdf_path)
        return summary_md_path, summary_pdf_path
