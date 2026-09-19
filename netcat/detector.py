import time
import queue
import logging
import threading
from collections import defaultdict
from netcat.dpi import DPIEngine, AppType

class ThreatEvent:
    def __init__(self, timestamp, src_ip, rule, severity, detail, alert_id=None):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.rule = rule
        self.severity = severity
        self.detail = detail
        self.alert_id = alert_id

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "rule": self.rule,
            "severity": self.severity,
            "detail": self.detail,
            "alert_id": self.alert_id
        }

class ThreatDetector(threading.Thread):
    def __init__(self, packet_queue, alert_queue, stats_queue, config_manager, db_manager, block_manager):
        super().__init__()
        self.packet_queue = packet_queue
        self.alert_queue = alert_queue
        self.stats_queue = stats_queue
        self.config = config_manager
        self.db = db_manager
        self.block_manager = block_manager
        self.capture_thread = None
        self.daemon = True
        self.running = False
        
        # State tracking per source IP
        self.ip_ports = defaultdict(list)        # list of (timestamp, port)
        self.ip_syns = defaultdict(list)         # list of timestamp
        self.ip_icmps = defaultdict(list)        # list of timestamp
        self.ip_pkts = defaultdict(list)         # list of timestamp
        self.ip_dns = defaultdict(list)          # list of timestamp
        
        # Alert cooldown to avoid alert spamming (IP, rule) -> last_triggered_time
        self.alert_cooldowns = {}
        self.cooldown_duration = 5.0 # seconds
        
        # Performance/aggregated statistics
        self.total_packets = 0
        self.app_breakdown = defaultdict(int)
        self.ip_traffic = defaultdict(int)       # IP -> packet count
        
        # Rolling packet counts for PPS
        self.pps_window = []

    def stop(self):
        self.running = False

    def clean_old_records(self, now):
        # Clean port scans (5s window)
        for ip, records in list(self.ip_ports.items()):
            self.ip_ports[ip] = [r for r in records if now - r[0] <= self.config.get("port_scan_window", 5.0)]
            if not self.ip_ports[ip]:
                del self.ip_ports[ip]

        # Clean SYN flood (5s window)
        for ip, timestamps in list(self.ip_syns.items()):
            self.ip_syns[ip] = [t for t in timestamps if now - t <= self.config.get("syn_flood_window", 5.0)]
            if not self.ip_syns[ip]:
                del self.ip_syns[ip]

        # Clean ICMP flood (5s window)
        for ip, timestamps in list(self.ip_icmps.items()):
            self.ip_icmps[ip] = [t for t in timestamps if now - t <= self.config.get("icmp_flood_window", 5.0)]
            if not self.ip_icmps[ip]:
                del self.ip_icmps[ip]

        # Clean traffic spike (2s window)
        for ip, timestamps in list(self.ip_pkts.items()):
            self.ip_pkts[ip] = [t for t in timestamps if now - t <= self.config.get("traffic_spike_window", 2.0)]
            if not self.ip_pkts[ip]:
                del self.ip_pkts[ip]

        # Clean DNS flood (10s window)
        for ip, timestamps in list(self.ip_dns.items()):
            self.ip_dns[ip] = [t for t in timestamps if now - t <= self.config.get("dns_flood_window", 10.0)]
            if not self.ip_dns[ip]:
                del self.ip_dns[ip]

        # Clean PPS window (1s window)
        self.pps_window = [t for t in self.pps_window if now - t <= 1.0]

    def trigger_alert(self, now, src_ip, rule, severity, detail):
        cooldown_key = (src_ip, rule)
        if cooldown_key in self.alert_cooldowns:
            if now - self.alert_cooldowns[cooldown_key] < self.cooldown_duration:
                return # In cooldown, skip
                
        self.alert_cooldowns[cooldown_key] = now
        
        # Log to Database and get new alert ID
        alert_id = self.db.log_threat_event(src_ip, rule, severity, detail)
        
        # Create event
        timestamp_str = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now))
        event = ThreatEvent(timestamp_str, src_ip, rule, severity, detail, alert_id=alert_id)
        
        # Push to UI queue
        self.alert_queue.put(event)
        
        # Check automatic blocking
        self.evaluate_blocking(event)
        
        # Trigger background report generation (Priority 1 & 3)
        self.generate_incident_report(event)

    def generate_incident_report(self, event):
        if not event.alert_id:
            return
            
        def run_report_generation():
            try:
                matching_packets = []
                if hasattr(self, 'capture_thread') and self.capture_thread:
                    with self.capture_thread.lock:
                        for pkt in self.capture_thread.recent_scapy_packets:
                            from scapy.all import IP, IPv6
                            if pkt.haslayer(IP):
                                if pkt[IP].src == event.src_ip or pkt[IP].dst == event.src_ip:
                                    matching_packets.append(pkt)
                            elif pkt.haslayer(IPv6):
                                if pkt[IPv6].src == event.src_ip or pkt[IPv6].dst == event.src_ip:
                                    matching_packets.append(pkt)
                                    
                import os
                reports_dir = os.path.join(os.getcwd(), "reports")
                incidents_dir = os.path.join(reports_dir, "incidents")
                os.makedirs(incidents_dir, exist_ok=True)
                
                pcap_path = os.path.join(incidents_dir, f"{event.alert_id}.pcap")
                
                # Audit trail: always log packet count so zero-match is distinguishable
                # from a silent exception (the 3.pcap investigation finding).
                if matching_packets:
                    logging.info(
                        f"Alert {event.alert_id}: {len(matching_packets)} matching packets "
                        f"found in rolling buffer for IP {event.src_ip}. Writing pcap."
                    )
                else:
                    logging.warning(
                        f"Alert {event.alert_id}: 0 matching packets in rolling buffer for "
                        f"IP {event.src_ip}. pcap will be empty (24-byte global header only). "
                        f"This is expected if the alert was triggered before any traffic from "
                        f"this IP entered the rolling buffer (e.g., synthetic alert or buffer cleared)."
                    )
                
                from scapy.all import wrpcap
                wrpcap(pcap_path, matching_packets)
                
                # Generate JSON, Markdown, and PDF
                from netcat.report_generator import ReportGenerator
                ReportGenerator.generate_report(event.alert_id, event, pcap_path)
            except Exception as ex:
                logging.error(f"Error in background incident report generator: {ex}", exc_info=True)
                
        threading.Thread(target=run_report_generation, daemon=True, name=f"ReportGen-{event.alert_id}").start()

    def evaluate_blocking(self, event):
        # Check if auto-blocking is globally enabled in configuration
        if not self.config.get("auto_block_enabled", True):
            return

        # Whitelist protection
        if self.config.is_whitelisted(event.src_ip):
            return
            
        severity_ranks = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        block_threshold = self.config.get("auto_block_severity", "high").lower()
        
        if block_threshold == "none":
            return
            
        event_rank = severity_ranks.get(event.severity.lower(), 0)
        threshold_rank = severity_ranks.get(block_threshold, 99) # default to high threshold
        
        if event_rank >= threshold_rank:
            # Trigger block
            if self.config.get("safe_mode", True):
                logging.info(f"[SAFE MODE] Alert severity {event.severity} crossed threshold. Would block {event.src_ip} (Reason: {event.rule}).")
            else:
                logging.info(f"Auto-blocking {event.src_ip} (Reason: {event.rule}).")
                self.block_manager.block_ip(event.src_ip, reason=f"Auto-blocked due to {event.rule}")

    def run(self):
        self.running = True
        logging.info("Threat detector thread started.")
        
        last_clean_time = time.time()
        last_stats_time = time.time()
        
        while self.running:
            try:
                # Grab packet from queue
                try:
                    pkt = self.packet_queue.get(timeout=0.1)
                except queue.Empty:
                    # Clean and report statistics periodically even if no packet
                    now = time.time()
                    if now - last_clean_time >= 1.0:
                        self.clean_old_records(now)
                        last_clean_time = now
                    if now - last_stats_time >= 0.5:
                        self.send_stats()
                        last_stats_time = now
                    continue

                now = pkt["timestamp"]
                src_ip = pkt["src_ip"]
                dst_ip = pkt["dst_ip"]
                protocol = pkt["protocol"]
                src_port = pkt["src_port"]
                dst_port = pkt["dst_port"]
                payload = pkt["payload"]
                is_syn = pkt["is_syn"]
                is_ack = pkt["is_ack"]
                is_icmp_echo = pkt["is_icmp_echo"]
                
                self.total_packets += 1
                self.pps_window.append(now)
                
                # Push a sample of packets to the GUI traffic queue (max 30 pkts/sec) to avoid lag
                if hasattr(self, 'traffic_queue') and self.traffic_queue is not None:
                    current_time = time.time()
                    if not hasattr(self, '_last_gui_traffic_time'):
                        self._last_gui_traffic_time = 0
                    if current_time - self._last_gui_traffic_time >= 0.033:  # ~30 Hz sampling
                        self._last_gui_traffic_time = current_time
                        if self.traffic_queue.qsize() >= 100:
                            try:
                                self.traffic_queue.get_nowait()
                            except queue.Empty:
                                pass
                        self.traffic_queue.put(pkt)
                
                # Check blacklist immediately
                if self.config.is_blocked(src_ip):
                    self.trigger_alert(
                        now, src_ip, "Blacklisted Traffic", "critical", 
                        f"Traffic detected from blacklisted IP address to port {dst_port}"
                    )
                    # We still parse it for statistics
                
                # Run DPI Classification
                app, domain = DPIEngine.classify_packet(protocol, dst_port, src_port, payload, src_ip, dst_ip)
                
                # Update stats
                self.app_breakdown[app] += 1
                self.ip_traffic[src_ip] += 1
                
                # Check whitelist protection - we do not raise behavioral alerts for whitelisted IPs,
                # but we parse DPI blocking rule matches if they match a domain block rule.
                is_whitelisted = self.config.is_whitelisted(src_ip)
                
                # --- Behavioral Checks (Skip if source IP is whitelisted) ---
                if not is_whitelisted:
                    # 1. Port Scan Check
                    if protocol == 6 or protocol == 17: # TCP or UDP
                        self.ip_ports[src_ip].append((now, dst_port))
                        distinct_ports = len(set(p[1] for p in self.ip_ports[src_ip]))
                        if distinct_ports >= self.config.get("port_scan_threshold", 15):
                            self.trigger_alert(
                                now, src_ip, "Port Scan", "medium",
                                f"Scanned {distinct_ports} distinct ports within last {self.config.get('port_scan_window', 5.0)}s"
                            )

                    # 2. SYN Flood Check
                    if protocol == 6 and is_syn and not is_ack:
                        self.ip_syns[src_ip].append(now)
                        syn_count = len(self.ip_syns[src_ip])
                        if syn_count >= self.config.get("syn_flood_threshold", 100):
                            self.trigger_alert(
                                now, src_ip, "SYN Flood", "high",
                                f"Sent {syn_count} TCP SYN packets in last {self.config.get('syn_flood_window', 5.0)}s"
                            )

                    # 3. ICMP Flood Check
                    if protocol == 1 and is_icmp_echo:
                        self.ip_icmps[src_ip].append(now)
                        icmp_count = len(self.ip_icmps[src_ip])
                        if icmp_count >= self.config.get("icmp_flood_threshold", 50):
                            self.trigger_alert(
                                now, src_ip, "ICMP Flood", "medium",
                                f"Sent {icmp_count} ICMP echo requests in last {self.config.get('icmp_flood_window', 5.0)}s"
                            )

                    # 4. Traffic Spike Check
                    self.ip_pkts[src_ip].append(now)
                    pkt_count = len(self.ip_pkts[src_ip])
                    spike_window = self.config.get("traffic_spike_window", 2.0)
                    pps = pkt_count / spike_window
                    if pkt_count >= self.config.get("traffic_spike_threshold", 500):
                        self.trigger_alert(
                            now, src_ip, "Traffic Spike", "low",
                            f"Traffic spike: {int(pps)} pkt/s (total {pkt_count} packets in {spike_window}s)"
                        )

                    # 5. DNS Flood Check
                    if protocol == 17 and (dst_port == 53 or src_port == 53):
                        self.ip_dns[src_ip].append(now)
                        dns_count = len(self.ip_dns[src_ip])
                        if dns_count >= self.config.get("dns_flood_threshold", 40):
                            self.trigger_alert(
                                now, src_ip, "DNS Flood", "medium",
                                f"Sent {dns_count} DNS queries in last {self.config.get('dns_flood_window', 10.0)}s"
                            )

                # --- DPI & Domain Checks (Apply to all, including whitelisted if domain is explicitly blocked) ---
                # 6. DNS Long Query Check
                if app == AppType.DNS and domain:
                    if len(domain) >= self.config.get("dns_long_query_threshold", 60):
                        self.trigger_alert(
                            now, src_ip, "Suspicious DNS Query", "low",
                            f"Excessively long DNS query name ({len(domain)} chars): {domain[:40]}..."
                        )
                
                # 7. DPI-flagged application / Domain block check
                blocked_apps = self.config.get("blocked_apps", [])
                blocked_domains = self.config.get("blocked_domains", [])
                
                if app in blocked_apps:
                    self.trigger_alert(
                        now, src_ip, "Blocked Application", "high",
                        f"Blocked application traffic detected: {app}"
                    )
                    
                if domain:
                    for d in blocked_domains:
                        if d in domain:
                            self.trigger_alert(
                                now, src_ip, "Blocked Domain", "high",
                                f"Traffic detected to blocked domain {domain} (matched rule: {d})"
                            )
                            break

                # Periodically clean old records
                if now - last_clean_time >= 1.0:
                    self.clean_old_records(now)
                    last_clean_time = now

                # Periodically send statistics to UI
                if now - last_stats_time >= 0.5:
                    self.send_stats()
                    last_stats_time = now

            except Exception as e:
                logging.error(f"Error in threat detection loop: {e}")
        
        logging.info("Threat detector thread stopped.")

    def send_stats(self):
        pps = len(self.pps_window)
        
        # Sort top talkers by packet count
        top_talkers = sorted(self.ip_traffic.items(), key=lambda x: x[1], reverse=True)[:5]
        
        stats = {
            "pps": pps,
            "total_packets": self.total_packets,
            "app_breakdown": dict(self.app_breakdown),
            "top_talkers": top_talkers
        }
        
        # Flush queue and insert latest stats to avoid lagging
        while not self.stats_queue.empty():
            try:
                self.stats_queue.get_nowait()
            except queue.Empty:
                break
                
        self.stats_queue.put(stats)
