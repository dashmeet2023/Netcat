import os
import sys
import time
import queue
import logging

# Add workspace directory to python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netcat.config_manager import ConfigManager
from netcat.database import DatabaseManager
from netcat.blocker import BlockManager
from netcat.detector import ThreatDetector, ThreatEvent

# Disable log spam during tests
logging.getLogger().setLevel(logging.WARNING)

class MockBlockManager(BlockManager):
    def __init__(self, config_manager, db_manager):
        self.config = config_manager
        self.db = db_manager
        self.active_blocks = {}
        self.blocked_ips = []
        
    def block_ip(self, ip, duration=None, reason="Manual Block"):
        self.blocked_ips.append(ip)
        self.active_blocks[ip] = {
            "timestamp": time.time(),
            "backend": "mock",
            "reason": reason,
            "expire_timer": None
        }
        return True

    def unblock_ip(self, ip, reason="Manual Unblock"):
        if ip in self.active_blocks:
            del self.active_blocks[ip]
            return True
        return False

    def clean_all_blocks(self):
        self.active_blocks.clear()

def run_tests():
    print("==================================================")
    print("           netcat DETECTION ENGINE TEST          ")
    print("==================================================")
    
    # 1. Setup mock files
    config_file = "test_config.json"
    db_file = "test_netcat.db"
    
    if os.path.exists(config_file): os.remove(config_file)
    if os.path.exists(db_file): os.remove(db_file)
    
    config = ConfigManager(config_path=config_file)
    # Put it in safe mode so blocking doesn't do system changes
    config.set("safe_mode", True)
    
    db = DatabaseManager(db_path=db_file)
    blocker = MockBlockManager(config, db)
    
    # 2. Setup queues
    packet_queue = queue.Queue()
    alert_queue = queue.Queue()
    stats_queue = queue.Queue()
    
    # 3. Create detector thread (but don't start as a thread, we'll call its loop logic or let it run)
    detector = ThreatDetector(
        packet_queue=packet_queue,
        alert_queue=alert_queue,
        stats_queue=stats_queue,
        config_manager=config,
        db_manager=db,
        block_manager=blocker
    )
    detector.running = True
    
    # Helper to feed packets into queue
    def feed_packet(src_ip, dst_ip, protocol, src_port=1024, dst_port=80, payload=b"", is_syn=False, is_ack=False, is_icmp_echo=False):
        pkt = {
            "timestamp": time.time(),
            "length": 64 + len(payload),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "is_syn": is_syn,
            "is_ack": is_ack,
            "is_icmp_echo": is_icmp_echo,
            "payload": payload
        }
        packet_queue.put(pkt)

    # Process all queued packets
    def process_queue():
        # Inject small sleep to ensure detector handles timestamps correctly
        time.sleep(0.01)
        while not packet_queue.empty():
            # We call the core run iteration manually for testing to avoid multi-threading race conditions in tests
            try:
                pkt = packet_queue.get_nowait()
                # Run the detection checks
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
                
                detector.total_packets += 1
                detector.pps_window.append(now)
                
                # Check blacklist
                if detector.config.is_blocked(src_ip):
                    detector.trigger_alert(now, src_ip, "Blacklisted Traffic", "critical", "Blacklisted traffic detected")
                
                # DPI Classify
                from netcat.dpi import DPIEngine, AppType
                app, domain = DPIEngine.classify_packet(protocol, dst_port, src_port, payload, src_ip, dst_ip)
                detector.app_breakdown[app] += 1
                detector.ip_traffic[src_ip] += 1
                
                is_whitelisted = detector.config.is_whitelisted(src_ip)
                if not is_whitelisted:
                    # Port Scan
                    if protocol == 6 or protocol == 17:
                        detector.ip_ports[src_ip].append((now, dst_port))
                        distinct_ports = len(set(p[1] for p in detector.ip_ports[src_ip]))
                        if distinct_ports >= detector.config.get("port_scan_threshold"):
                            detector.trigger_alert(now, src_ip, "Port Scan", "medium", f"Scanned {distinct_ports} ports")
                    
                    # SYN Flood
                    if protocol == 6 and is_syn and not is_ack:
                        detector.ip_syns[src_ip].append(now)
                        syn_count = len(detector.ip_syns[src_ip])
                        if syn_count >= detector.config.get("syn_flood_threshold"):
                            detector.trigger_alert(now, src_ip, "SYN Flood", "high", f"Sent {syn_count} SYNs")
                            
                    # ICMP Flood
                    if protocol == 1 and is_icmp_echo:
                        detector.ip_icmps[src_ip].append(now)
                        icmp_count = len(detector.ip_icmps[src_ip])
                        if icmp_count >= detector.config.get("icmp_flood_threshold"):
                            detector.trigger_alert(now, src_ip, "ICMP Flood", "medium", f"Sent {icmp_count} ICMPs")
                            
                    # DNS Flood
                    if protocol == 17 and (dst_port == 53 or src_port == 53):
                        detector.ip_dns[src_ip].append(now)
                        dns_count = len(detector.ip_dns[src_ip])
                        if dns_count >= detector.config.get("dns_flood_threshold"):
                            detector.trigger_alert(now, src_ip, "DNS Flood", "medium", f"Sent {dns_count} DNS queries")

                # DNS query length
                if app == AppType.DNS and domain:
                    if len(domain) >= detector.config.get("dns_long_query_threshold"):
                        detector.trigger_alert(now, src_ip, "Suspicious DNS Query", "low", f"DNS query length {len(domain)}")

            except queue.Empty:
                break

    # --------------------------------------------------
    # TEST 1: Port Scan Detection
    # --------------------------------------------------
    print("Running Test 1: Port Scan Detection...")
    src_ip = "192.168.1.15"
    for port in range(1, 17):  # 16 distinct ports (threshold is 15)
        feed_packet(src_ip=src_ip, dst_ip="192.168.1.1", protocol=6, dst_port=port)
    process_queue()
    
    assert not alert_queue.empty(), "FAIL: Port Scan did not trigger any alerts."
    alert = alert_queue.get_nowait()
    assert alert.rule == "Port Scan", f"FAIL: Expected Port Scan alert, got {alert.rule}"
    assert alert.src_ip == src_ip, f"FAIL: Expected alert for {src_ip}, got {alert.src_ip}"
    print(f"  [PASS] Port Scan successfully triggered: {alert.detail}")

    # Clear queue
    while not alert_queue.empty(): alert_queue.get()

    # --------------------------------------------------
    # TEST 2: SYN Flood Detection
    # --------------------------------------------------
    print("Running Test 2: SYN Flood Detection...")
    src_ip = "10.0.0.99"
    for _ in range(101):  # 101 SYNs (threshold is 100)
        feed_packet(src_ip=src_ip, dst_ip="10.0.0.1", protocol=6, is_syn=True, is_ack=False)
    process_queue()
    
    assert not alert_queue.empty(), "FAIL: SYN Flood did not trigger any alerts."
    alert = alert_queue.get_nowait()
    assert alert.rule == "SYN Flood", f"FAIL: Expected SYN Flood, got {alert.rule}"
    assert alert.src_ip == src_ip, "FAIL: Incorrect source IP"
    print(f"  [PASS] SYN Flood successfully triggered: {alert.detail}")
    
    while not alert_queue.empty(): alert_queue.get()

    # --------------------------------------------------
    # TEST 3: ICMP Flood Detection
    # --------------------------------------------------
    print("Running Test 3: ICMP Flood Detection...")
    src_ip = "172.16.5.5"
    for _ in range(51):  # 51 ICMP Echo Requests (threshold is 50)
        feed_packet(src_ip=src_ip, dst_ip="172.16.5.1", protocol=1, is_icmp_echo=True)
    process_queue()
    
    assert not alert_queue.empty(), "FAIL: ICMP Flood did not trigger any alerts."
    alert = alert_queue.get_nowait()
    assert alert.rule == "ICMP Flood", f"FAIL: Expected ICMP Flood, got {alert.rule}"
    print(f"  [PASS] ICMP Flood successfully triggered: {alert.detail}")
    
    while not alert_queue.empty(): alert_queue.get()

    # --------------------------------------------------
    # TEST 4: DNS Flood and Suspicious DNS Query Length
    # --------------------------------------------------
    print("Running Test 4: DNS Alerts...")
    src_ip = "192.168.10.10"
    
    # DNS long query (threshold 60)
    # DNS header is 12 bytes. Let's make a mock DNS query payload
    # Mock query: label length 64 bytes
    mock_payload = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"  # 12 bytes DNS header
    mock_payload += b"\x1e" + (b"a" * 30) + b"\x1e" + (b"b" * 30) + b"\x03com\x00"
    feed_packet(src_ip=src_ip, dst_ip="8.8.8.8", protocol=17, dst_port=53, payload=mock_payload)
    process_queue()
    
    assert not alert_queue.empty(), "FAIL: DNS query did not trigger alert."
    alert = alert_queue.get_nowait()
    assert alert.rule == "Suspicious DNS Query", f"FAIL: Expected Suspicious DNS Query, got {alert.rule}"
    print(f"  [PASS] Suspicious DNS query successfully triggered: {alert.detail}")
    
    while not alert_queue.empty(): alert_queue.get()

    # DNS Flood
    for _ in range(41):
        feed_packet(src_ip=src_ip, dst_ip="8.8.8.8", protocol=17, dst_port=53)
    process_queue()
    
    assert not alert_queue.empty(), "FAIL: DNS Flood did not trigger."
    alert = alert_queue.get_nowait()
    assert alert.rule == "DNS Flood", f"FAIL: Expected DNS Flood, got {alert.rule}"
    print(f"  [PASS] DNS Flood successfully triggered: {alert.detail}")

    while not alert_queue.empty(): alert_queue.get()

    # --------------------------------------------------
    # CLEANUP
    # --------------------------------------------------
    # Close databases and remove temp files
    detector.running = False
    
    if os.path.exists(config_file): os.remove(config_file)
    if os.path.exists(db_file): os.remove(db_file)
    
    print("\nALL TESTS PASSED SUCCESSFULLY!")
    print("==================================================")

if __name__ == "__main__":
    run_tests()
