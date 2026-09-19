import os
import sys
import time
import queue
import unittest
import shutil
from scapy.all import Packet, IP, TCP, Raw

# Add workspace directory to python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netcat.config_manager import ConfigManager
from netcat.database import DatabaseManager
from netcat.blocker import BlockManager
from netcat.detector import ThreatDetector
from netcat.report_generator import ReportGenerator

class MockBlockManager(BlockManager):
    def __init__(self, config_manager, db_manager):
        self.config = config_manager
        self.db = db_manager
        self.blocked_ips = []
        
    def block_ip(self, ip, duration=None, reason="Manual Block"):
        self.blocked_ips.append(ip)
        return True

class MockCaptureThread:
    def __init__(self):
        self.lock = threading_lock = type('Lock', (object,), {'__enter__': lambda s: None, '__exit__': lambda s, a, b, c: None})()
        # Mock some scapy packets
        from scapy.all import Ether, IP, TCP
        pkt1 = Ether()/IP(src="192.168.10.15", dst="8.8.8.8")/TCP(sport=12345, dport=443)
        pkt2 = Ether()/IP(src="8.8.8.8", dst="192.168.10.15")/TCP(sport=443, dport=12345)
        # Set timestamp field as floats (scapy requires time field to write)
        pkt1.time = time.time()
        pkt2.time = time.time()
        self.recent_scapy_packets = [pkt1, pkt2]

class TestForensicSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Setup clean test config and database files
        cls.config_file = "test_forensics_config.json"
        cls.db_file = "test_forensics_netcat.db"
        
        if os.path.exists(cls.config_file): os.remove(cls.config_file)
        if os.path.exists(cls.db_file): os.remove(cls.db_file)
        
        # Clean reports directories from previous runs
        reports_dir = os.path.join(os.getcwd(), "reports")
        if os.path.exists(reports_dir):
            try:
                shutil.rmtree(reports_dir)
            except Exception:
                pass
        
        cls.config = ConfigManager(config_path=cls.config_file)
        cls.db = DatabaseManager(db_path=cls.db_file)
        ReportGenerator.db_manager = cls.db
        
    @classmethod
    def tearDownClass(cls):
        # Wait for all background report generation threads to finish to avoid file lock issues
        import threading
        for t in threading.enumerate():
            if t.name.startswith("ReportGen-"):
                t.join(timeout=5.0)

        if os.path.exists(cls.config_file): os.remove(cls.config_file)
        if os.path.exists(cls.db_file): os.remove(cls.db_file)
        # Clean reports directories created during test run
        reports_dir = os.path.join(os.getcwd(), "reports")
        if os.path.exists(reports_dir):
            try:
                shutil.rmtree(reports_dir)
            except Exception:
                pass

    def test_priority0_regression_gating(self):
        """
        Verify that C++ rule match block events are gated by safe_mode.
        """
        # Test Case A: safe_mode = True (Alert should log, but block_ip NOT called)
        self.config.set("safe_mode", True)
        self.config.set("auto_block_enabled", True)
        self.config.set("auto_block_severity", "high")
        
        mock_blocker = MockBlockManager(self.config, self.db)
        
        detector = ThreatDetector(
            packet_queue=queue.Queue(),
            alert_queue=queue.Queue(),
            stats_queue=queue.Queue(),
            config_manager=self.config,
            db_manager=self.db,
            block_manager=mock_blocker
        )
        
        # Trigger C++ rule block event
        detector.trigger_alert(
            now=time.time(),
            src_ip="198.51.100.1",
            rule="C++ DPI Rule Match",
            severity="high",
            detail="C++ DPI rule triggered block"
        )
        
        # Confirm that the blocker was not invoked under safe_mode
        self.assertNotIn("198.51.100.1", mock_blocker.blocked_ips)
        
        # Test Case B: safe_mode = False (Alert should trigger auto block_ip)
        self.config.set("safe_mode", False)
        
        detector.trigger_alert(
            now=time.time() + 10.0, # shift time to avoid cooldown filter
            src_ip="198.51.100.2",
            rule="C++ DPI Rule Match",
            severity="high",
            detail="C++ DPI rule triggered block"
        )
        
        # Confirm that the blocker was successfully called
        self.assertIn("198.51.100.2", mock_blocker.blocked_ips)

    def test_priority1_incident_pcap_extraction(self):
        """
        Verify that relevant packets are extracted and written to a pcap file asynchronously.
        """
        mock_blocker = MockBlockManager(self.config, self.db)
        detector = ThreatDetector(
            packet_queue=queue.Queue(),
            alert_queue=queue.Queue(),
            stats_queue=queue.Queue(),
            config_manager=self.config,
            db_manager=self.db,
            block_manager=mock_blocker
        )
        detector.capture_thread = MockCaptureThread()
        
        # Trigger alert which calls generate_incident_report
        detector.trigger_alert(
            now=time.time(),
            src_ip="192.168.10.15",
            rule="SYN Flood Alert",
            severity="high",
            detail="Test SYN Flood"
        )
        
        # Wait a moment for background thread to write files, polling for size > 24
        reports_dir = os.path.join(os.getcwd(), "reports")
        incidents_dir = os.path.join(reports_dir, "incidents")
        pcap_path = os.path.join(incidents_dir, "3.pcap") # Alert ID is 3 (1 and 2 from A/B tests)
        
        timeout = 5.0
        start_t = time.time()
        while time.time() - start_t < timeout:
            if os.path.exists(pcap_path) and os.path.getsize(pcap_path) > 24:
                break
            time.sleep(0.1)
            
        self.assertTrue(os.path.exists(pcap_path), "Asynchronous incident pcap should be generated")
        self.assertGreater(os.path.getsize(pcap_path), 24, "Incident pcap should contain serialized packets")

    def test_priority3_report_compilers(self):
        """
        Verify that forensic Markdown and PDF reports are compiled successfully.
        """
        # Retrieve the pcap generated by test_priority1
        reports_dir = os.path.join(os.getcwd(), "reports")
        pcap_path = os.path.join(reports_dir, "incidents", "3.pcap")
        
        self.assertTrue(os.path.exists(pcap_path), "Pre-requisite pcap file must exist")
        
        # Instantiate alert metadata
        from netcat.detector import ThreatEvent
        event = ThreatEvent(
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
            src_ip="192.168.10.15",
            rule="SYN Flood Alert",
            severity="high",
            detail="Test SYN Flood detail information",
            alert_id=3
        )
        
        # Trigger report generation (pure-Python fallback will execute as C++ is not built on sandbox yet)
        ReportGenerator._cooldowns.clear()
        ReportGenerator.generate_report(3, event, pcap_path)
        
        # Check database analysis logs
        json_log = self.db.get_threat_analysis(3)
        self.assertIsNotNone(json_log, "Database should contain serialized threat JSON analysis")
        
        # Verify markdown file exists
        md_path = os.path.join(reports_dir, "3.md")
        self.assertTrue(os.path.exists(md_path), "Markdown report file must be written")
        
        # Verify PDF file exists
        pdf_path = os.path.join(reports_dir, "3.pdf")
        self.assertTrue(os.path.exists(pdf_path), "PDF report file must be compiled")
        self.assertGreater(os.path.getsize(pdf_path), 1000, "PDF should not be empty")

if __name__ == '__main__':
    unittest.main()
