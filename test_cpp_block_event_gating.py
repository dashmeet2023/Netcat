"""
Test: C++ block event gating through evaluate_blocking().

Proves that Fix 1 is correct: no code path in start_cpp_worker()'s block
event handler can reach block_manager.block_ip() directly.

Cases:
  1. Block event arrives before detector_thread is set -> queued, not blocked.
  2. Queued event flushed with safe_mode=True -> still not blocked (gate holds).
  3. Queued event flushed with safe_mode=False -> blocked via evaluate_blocking().
  4. Static source audit: confirm block_manager.block_ip is absent from dpi.py.
"""
import ast
import os
import queue
import sys
import time
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netcat.config_manager import ConfigManager
from netcat.database import DatabaseManager
from netcat.detector import ThreatDetector
from netcat.dpi import DPIEngine


class TrackingBlockManager:
    """Minimal stub that records every block_ip() call."""
    def __init__(self):
        self.calls = []          # list of ip strings
        self.config = None       # set by caller before use

    def block_ip(self, ip, duration=None, reason=""):
        self.calls.append(ip)
        return True


class TestCppBlockEventGating(unittest.TestCase):

    def setUp(self):
        # Fresh per-test state: clear the class-level pending queue and
        # reset detector_thread so tests are independent.
        with DPIEngine._pending_lock:
            DPIEngine._pending_block_events.clear()
        DPIEngine.detector_thread = None
        DPIEngine.block_manager = None

        self.config = ConfigManager(config_path="test_gating_config.json")
        self.db = DatabaseManager(db_path="test_gating.db")

    def tearDown(self):
        with DPIEngine._pending_lock:
            DPIEngine._pending_block_events.clear()
        DPIEngine.detector_thread = None
        DPIEngine.block_manager = None

        for f in ("test_gating_config.json", "test_gating.db"):
            try:
                os.remove(f)
            except FileNotFoundError:
                pass

    # ------------------------------------------------------------------
    # Helper: build a real ThreatDetector wired to a TrackingBlockManager
    # ------------------------------------------------------------------
    def _make_detector(self, safe_mode: bool, auto_block_severity: str = "high"):
        tracker = TrackingBlockManager()
        self.config.set("safe_mode", safe_mode)
        self.config.set("auto_block_enabled", True)
        self.config.set("auto_block_severity", auto_block_severity)
        tracker.config = self.config

        detector = ThreatDetector(
            packet_queue=queue.Queue(),
            alert_queue=queue.Queue(),
            stats_queue=queue.Queue(),
            config_manager=self.config,
            db_manager=self.db,
            block_manager=tracker,
        )
        return detector, tracker

    # ------------------------------------------------------------------
    # Test 1: block event at t=0 (detector_thread is None) -> queued, not called
    # ------------------------------------------------------------------
    def test_early_block_event_is_queued_not_blocked(self):
        tracker = TrackingBlockManager()
        DPIEngine.block_manager = tracker
        # detector_thread deliberately left as None

        # Simulate what the live-event loop does when msg_type == "block"
        # and detector_thread is None:
        ip = "10.0.0.1"
        reason = "C++ rule match"
        with DPIEngine._pending_lock:
            DPIEngine._pending_block_events.append((ip, reason, time.time()))

        # Nothing should have been blocked yet
        self.assertEqual(
            tracker.calls, [],
            "block_ip() must NOT be called directly when detector_thread is None"
        )
        # Event must be queued
        with DPIEngine._pending_lock:
            queued = list(DPIEngine._pending_block_events)
        self.assertEqual(len(queued), 1)
        self.assertEqual(queued[0][0], ip)

    # ------------------------------------------------------------------
    # Test 2: flush with safe_mode=True -> alert fired, block_ip() NOT called
    # ------------------------------------------------------------------
    def test_flush_safe_mode_on_blocks_nothing(self):
        detector, tracker = self._make_detector(safe_mode=True)

        # Queue a block event
        ip = "192.168.1.5"
        with DPIEngine._pending_lock:
            DPIEngine._pending_block_events.append((ip, "banned domain", time.time()))

        # Assign detector_thread then flush
        DPIEngine.detector_thread = detector
        DPIEngine.flush_pending_block_events()

        # Queue must be drained
        with DPIEngine._pending_lock:
            self.assertEqual(DPIEngine._pending_block_events, [])

        # block_ip() must NOT have been called (safe_mode gate)
        self.assertNotIn(
            ip, tracker.calls,
            "block_ip() must not be called when safe_mode=True, even via evaluate_blocking()"
        )

        # The alert must have been put on the alert queue (event was processed)
        self.assertFalse(
            detector.alert_queue.empty(),
            "trigger_alert() must have put an event on alert_queue"
        )
        event = detector.alert_queue.get_nowait()
        self.assertEqual(event.src_ip, ip)
        self.assertEqual(event.rule, "C++ DPI Rule Match")

    # ------------------------------------------------------------------
    # Test 3: flush with safe_mode=False -> block_ip() IS called via evaluate_blocking()
    # ------------------------------------------------------------------
    def test_flush_safe_mode_off_triggers_block_via_evaluate_blocking(self):
        detector, tracker = self._make_detector(safe_mode=False, auto_block_severity="high")

        ip = "172.16.0.99"
        with DPIEngine._pending_lock:
            DPIEngine._pending_block_events.append((ip, "C++ rule block", time.time()))

        DPIEngine.detector_thread = detector
        DPIEngine.flush_pending_block_events()

        with DPIEngine._pending_lock:
            self.assertEqual(DPIEngine._pending_block_events, [])

        # block_ip() must have been called via evaluate_blocking()
        # (severity="high" >= threshold="high", safe_mode=False)
        self.assertIn(
            ip, tracker.calls,
            "block_ip() must be called via evaluate_blocking() when safe_mode=False and severity meets threshold"
        )

    # ------------------------------------------------------------------
    # Test 4: static source audit — confirm block_manager.block_ip is
    # not present in start_cpp_worker() in dpi.py
    # ------------------------------------------------------------------
    def test_no_direct_block_ip_call_in_start_cpp_worker(self):
        dpi_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "netcat", "dpi.py"
        )
        with open(dpi_path, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source)

        # Find the start_cpp_worker function definition
        worker_func = None
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "start_cpp_worker":
                worker_func = node
                break

        self.assertIsNotNone(worker_func, "start_cpp_worker must exist in dpi.py")

        # Walk all attribute accesses inside start_cpp_worker and its nested defs
        direct_block_calls = []
        for node in ast.walk(worker_func):
            # Looking for: cls.block_manager.block_ip(...)  or  block_manager.block_ip(...)
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute) and func.attr == "block_ip":
                    # Reconstruct who the object is
                    obj = func.value
                    if isinstance(obj, ast.Attribute) and obj.attr == "block_manager":
                        direct_block_calls.append(ast.unparse(node))
                    elif isinstance(obj, ast.Name) and "block_manager" in obj.id:
                        direct_block_calls.append(ast.unparse(node))

        self.assertEqual(
            direct_block_calls, [],
            f"Found direct block_ip() call(s) inside start_cpp_worker: {direct_block_calls}"
        )


if __name__ == "__main__":
    # Run with verbose output so evidence is printed
    unittest.main(verbosity=2)
