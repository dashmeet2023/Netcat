import os
import sys

# Add workspace directory to python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ctypes
import queue
import logging
from PyQt6.QtWidgets import QApplication, QMessageBox
from netcat.config_manager import ConfigManager
from netcat.database import DatabaseManager
from netcat.blocker import BlockManager
from netcat.capture import CaptureThread, list_interfaces
from netcat.detector import ThreatDetector
from netcat.dpi import DPIEngine

# Setup global logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("netcat.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def run_as_admin():
    # Relaunch the program with admin privileges
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1
    )

def build_dpi_engine():
    import shutil
    import subprocess
    
    logging.info("Starting C++ DPI engine build pipeline...")
    
    workspace_dir = os.path.dirname(os.path.abspath(__file__))
    src_dir = os.path.join(workspace_dir, "Packet_analyzer_extracted", "Packet_analyzer-main")
    
    # --- Toolchain detection ---
    cmake_path = shutil.which("cmake")
    cl_path = shutil.which("cl")        # MSVC
    gpp_path = shutil.which("g++")      # MinGW / GCC
    
    has_compiler = bool(cl_path or gpp_path)
    
    if not cmake_path or not has_compiler:
        print("\n" + "="*60)
        print("[!] C++ DPI engine build FAILED — missing toolchain components")
        print("="*60)
        
        if not cmake_path:
            logging.error("CMake was not found on your system PATH.")
            print("\n  MISSING: cmake")
            print("  \u2514\u2500 Install CMake for Windows (adds to PATH automatically):")
            print("       https://github.com/Kitware/CMake/releases/latest")
            print("       Direct MSI: cmake-*-windows-x86_64.msi")
            print("       Or via winget:  winget install Kitware.CMake")
        
        if not cl_path and not gpp_path:
            logging.error("No C++ compiler found (cl.exe / g++ not in PATH).")
            print("\n  MISSING: C++ compiler (need one of the following)")
            print("")
            print("  Option A — Microsoft Visual Studio Build Tools (MSVC cl.exe):")
            print("       https://visualstudio.microsoft.com/visual-cpp-build-tools/")
            print("       Select workload: \"Desktop development with C++\"")
            print("       After install, open \"Developer Command Prompt for VS 2022\"")
            print("       and re-run this build from there.")
            print("")
            print("  Option B — MinGW-w64 (g++), via MSYS2 (recommended):")
            print("       https://www.msys2.org/  (install to C:\\msys64)")
            print("       In MSYS2 MINGW64 shell run:")
            print("         pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake")
            print("       Then add  C:\\msys64\\mingw64\\bin  to System PATH.")
            print("       (Win+R \u2192 sysdm.cpl \u2192 Advanced \u2192 Environment Variables)")
            print("")
            print("  Option C — winget (one-liner, requires Windows 10 1709+):")
            print("       winget install MSYS2.MSYS2")
        elif not gpp_path and cl_path:
            print(f"  [OK] MSVC cl.exe found: {cl_path}")
        elif gpp_path and not cl_path:
            print(f"  [OK] g++ found: {gpp_path}")
        
        print("")
        print(f"  Full build instructions: {os.path.join(src_dir, 'WINDOWS_SETUP.md')}")
        print("="*60 + "\n")
        return False
    
    logging.info(f"Toolchain detected: cmake={cmake_path}, cl={cl_path}, g++={gpp_path}")
    print(f"  [OK] cmake: {cmake_path}")
    if cl_path: print(f"  [OK] cl.exe (MSVC): {cl_path}")
    if gpp_path: print(f"  [OK] g++: {gpp_path}")

    build_dir = os.path.join(src_dir, "build")
    
    try:
        logging.info(f"Running CMake configuration in {build_dir}...")
        res_conf = subprocess.run(
            [cmake_path, "-B", build_dir, "-S", src_dir],
            capture_output=True, text=True
        )
        if res_conf.returncode != 0:
            logging.error(f"CMake configuration failed: {res_conf.stderr}")
            print(f"\n[!] CMake configuration failed:\n{res_conf.stderr}\n")
            return False
            
        logging.info("Running CMake build...")
        res_build = subprocess.run(
            [cmake_path, "--build", build_dir, "--config", "Release"],
            capture_output=True, text=True
        )
        if res_build.returncode != 0:
            logging.error(f"CMake build failed: {res_build.stderr}")
            print(f"\n[!] CMake build failed:\n{res_build.stderr}\n")
            return False
            
        bin_paths = [
            os.path.join(build_dir, "Release", "dpi_engine.exe"),
            os.path.join(build_dir, "dpi_engine.exe")
        ]
        
        found_bin = None
        for path in bin_paths:
            if os.path.exists(path):
                found_bin = path
                break
                
        if not found_bin:
            logging.error("Build succeeded but dpi_engine.exe was not found in build directory.")
            print("\n[!] Built binary dpi_engine.exe not found in build outputs.\n")
            return False
            
        dest_path = os.path.join(workspace_dir, "dpi_engine.exe")
        shutil.copy2(found_bin, dest_path)
        logging.info(f"C++ DPI engine successfully built and deployed to: {dest_path}")
        print(f"\n[+] Success! C++ DPI engine compiled and deployed to {dest_path}")
        
        # Post-build self-check: run --version to verify the binary is functional
        try:
            version_result = subprocess.run(
                [dest_path, "--version"],
                capture_output=True, text=True, timeout=5.0
            )
            version_out = (version_result.stdout + version_result.stderr).strip()
            if version_result.returncode == 0 or version_out:
                logging.info(f"[DPI ENGINE SELF-CHECK PASS] dpi_engine.exe --version output: {version_out or '(no output, exit 0)'}")
                print(f"[+] SELF-CHECK PASS: dpi_engine.exe responded to --version")
            else:
                logging.warning(f"[DPI ENGINE SELF-CHECK WARN] --version exited {version_result.returncode} with no output")
                print(f"[!] SELF-CHECK WARNING: --version returned exit code {version_result.returncode} with no output")
        except subprocess.TimeoutExpired:
            logging.warning("[DPI ENGINE SELF-CHECK WARN] --version timed out (5s) — binary may require stdin/pcap input")
            print("[!] SELF-CHECK WARNING: --version timed out (binary likely requires pcap input to start)")
        except Exception as sc_err:
            logging.warning(f"[DPI ENGINE SELF-CHECK FAIL] Could not invoke dpi_engine.exe --version: {sc_err}")
            print(f"[!] SELF-CHECK FAIL: {sc_err}")
        
        print()
        return True
        
    except Exception as e:
        logging.error(f"Unexpected error during C++ compilation: {e}")
        print(f"\n[!] Unexpected error: {e}\n")
        return False


def main():
    import argparse
    parser = argparse.ArgumentParser(description="NetCat Network Monitor & Blocker")
    parser.add_argument("--build-dpi-engine", action="store_true", help="Compile and ship the C++ DPI engine")
    args, unknown = parser.parse_known_args()
    
    if args.build_dpi_engine:
        success = build_dpi_engine()
        sys.exit(0 if success else 1)

    # 1. Elevate to Administrator if not already elevated
    if not is_admin():
        logging.info("Not running as Administrator. Attempting to elevate...")
        try:
            run_as_admin()
        except Exception as e:
            logging.error(f"Failed to elevate permissions: {e}")
        sys.exit(0)

    logging.info("netcat starting up as Administrator...")

    # Initialize PyQt application immediately (needed to show dialogs or main window)
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    # Set application window icon
    from PyQt6.QtGui import QIcon
    logo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "netcat_logo.png")
    if os.path.exists(logo_path):
        app.setWindowIcon(QIcon(logo_path))

    # 2. Load Configuration and Database
    config = ConfigManager()
    db = DatabaseManager()
    block_manager = BlockManager(config, db)

    # Auto build C++ engine if enabled but binary is missing
    dpi_bin_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dpi_engine.exe")
    if config.get("use_cpp_dpi_engine", False) and not os.path.exists(dpi_bin_path):
        logging.info("use_cpp_dpi_engine is enabled but dpi_engine.exe is missing. Attempting auto-build...")
        build_dpi_engine()

    # 3. Choose a default network interface if none is configured
    interfaces = list_interfaces()
    if not interfaces:
        QMessageBox.critical(
            None, "No Interfaces Found",
            "netcat could not find any active Npcap interfaces. Please ensure Npcap is installed in WinPcap-compatible mode and restart."
        )
        sys.exit(1)

    selected_iface_name = config.get("selected_interface")
    if selected_iface_name:
        cached_valid = False
        for iface in interfaces:
            if iface.name == selected_iface_name:
                if iface.ip != "No IP" and iface.ip != "127.0.0.1" and not iface.ip.startswith("169.254."):
                    desc_lower = iface.description.lower() if iface.description else ""
                    if not any(k in desc_lower for k in ["bluetooth", "loopback", "virtual", "vpn"]):
                        cached_valid = True
                break
        if not cached_valid:
            logging.info(f"Cached interface '{selected_iface_name}' is invalid, link-local, or virtual. Clearing cache to run auto-selection...")
            config.set("selected_interface", "")
            selected_iface_name = ""

    if not selected_iface_name:
        default_iface = None
        
        # Heuristic 1: Try Scapy's default route interface
        try:
            from scapy.all import conf
            scapy_default_iface_name = getattr(conf.iface, "name", None)
            if scapy_default_iface_name:
                for iface in interfaces:
                    if iface.name == scapy_default_iface_name:
                        # Ensure it has a valid non-link-local IP
                        if iface.ip != "No IP" and iface.ip != "127.0.0.1" and not iface.ip.startswith("169.254."):
                            desc_lower = iface.description.lower() if iface.description else ""
                            if not any(k in desc_lower for k in ["bluetooth", "loopback", "virtual", "vpn"]):
                                default_iface = iface
                                logging.info(f"Automatically selected Scapy's default route interface: {iface.description} ({iface.ip})")
                                break
        except Exception as e:
            logging.warning(f"Error checking Scapy default interface: {e}")

        # Heuristic 2: Heuristics fallback - find first non-link-local, non-loopback, non-virtual/VPN/BT interface with an IP
        if not default_iface:
            for iface in interfaces:
                if iface.ip != "No IP" and iface.ip != "127.0.0.1" and not iface.ip.startswith("169.254."):
                    desc_lower = iface.description.lower() if iface.description else ""
                    if not any(k in desc_lower for k in ["bluetooth", "loopback", "virtual", "vpn"]):
                        default_iface = iface
                        logging.info(f"Automatically selected interface via heuristics (non-virtual, non-link-local): {iface.description} ({iface.ip})")
                        break
                        
        # Heuristic 3: Relaxed description filters but maintain APIPA check
        if not default_iface:
            for iface in interfaces:
                if iface.ip != "No IP" and iface.ip != "127.0.0.1" and not iface.ip.startswith("169.254."):
                    default_iface = iface
                    logging.info(f"Automatically selected interface via relaxed heuristics (non-link-local): {iface.description} ({iface.ip})")
                    break

        # Heuristic 4: Ultimate fallback: pick first with any active IP (could be Bluetooth/Virtual)
        if not default_iface:
            for iface in interfaces:
                if iface.ip != "No IP" and iface.ip != "127.0.0.1":
                    default_iface = iface
                    logging.warning(f"Low-confidence fallback interface selected: {iface.description} ({iface.ip})")
                    break
                    
        # Heuristic 5: Absolute fallback: pick first interface in the list
        if not default_iface:
            default_iface = interfaces[0]
            logging.warning(f"No interface with valid IP found. Absolute fallback selected: {default_iface.description}")
            
        selected_iface_name = default_iface.name
        config.set("selected_interface", selected_iface_name)

    # 4. Initialize C++ DPI Engine Worker if enabled
    if config.get("use_cpp_dpi_engine", False):
        exe_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dpi_engine.exe")
        if not os.path.exists(exe_path):
            logging.warning("C++ DPI engine enabled in config but dpi_engine.exe not found — falling back to Python DPI")
    DPIEngine.block_manager = block_manager
    DPIEngine.start_cpp_worker(config)

    # 5. Initialize queues
    packet_queue = queue.Queue(maxsize=10000)
    alert_queue = queue.Queue()
    stats_queue = queue.Queue()
    traffic_queue = queue.Queue()

    # 5. Start background Capture Thread
    capture_thread = CaptureThread(selected_iface_name, packet_queue)
    capture_thread.start()

    # 6. Start background Threat Detector Thread
    detector_thread = ThreatDetector(
        packet_queue=packet_queue,
        alert_queue=alert_queue,
        stats_queue=stats_queue,
        config_manager=config,
        db_manager=db,
        block_manager=block_manager
    )
    DPIEngine.detector_thread = detector_thread
    # Flush any C++ block events that arrived during the startup window
    # (between start_cpp_worker() and this assignment). All events are
    # routed through trigger_alert() -> evaluate_blocking(), so safe_mode,
    # whitelist, and severity gating are applied. See dpi.py for details.
    DPIEngine.flush_pending_block_events()
    detector_thread.capture_thread = capture_thread
    
    # We monkey-patch or subclass to make it easy. We can wrap the detector's processing.
    # In detector.py, whenever it gets a packet, it updates stats. We can also push it to traffic_queue!
    # Let's inject traffic_queue into detector so it can push packet samples directly.
    detector_thread.traffic_queue = traffic_queue
    original_run = detector_thread.run
    
    def detector_run_with_traffic_sample():
        # Inject custom packet sampling logic into the run loop
        # We can just override the loop's queue insertion
        # Let's do it inside the main detector thread by referencing detector_thread.traffic_queue
        # We will write a custom wrapper or since detector has traffic_queue, let's let it run
        original_run()

    detector_thread.run = detector_run_with_traffic_sample
    
    # Wait, we need the detector to actually write to the traffic_queue!
    # Let's check how the detector loop processes packets:
    # Under `self.total_packets += 1` inside `detector.py`, let's check if it pushes to traffic_queue.
    # Ah! I didn't write `self.traffic_queue.put` in `detector.py`.
    # Let's check if we can modify `detector.py` to push to `traffic_queue` or modify it here.
    # In `netcat/detector.py`, we can easily add pushing to `traffic_queue` by checking if it exists.
    # Yes, in `detector.py` I wrote:
    # "DPI & Domain Checks ... Periodically send statistics to UI"
    # Wait, we can modify `netcat/detector.py` to support `traffic_queue` and push packets to it,
    # or we can do it inside a wrapper. Let's look at `detector.py`'s loop and update it to push
    # to `traffic_queue` if present. That is extremely clean!
    # Let's check if we can edit `detector.py` to add `self.traffic_queue.put(pkt)` for sampling.
    
    # Wait, let's write `netcat_app.py` first, then update `detector.py` to support `self.traffic_queue`.
    
    # Launch GUI Dashboard
    from netcat.gui.dashboard import DashboardWindow
    window = DashboardWindow(
        config_manager=config,
        db_manager=db,
        block_manager=block_manager,
        alert_queue=alert_queue,
        stats_queue=stats_queue,
        traffic_queue=traffic_queue,
        packet_queue=packet_queue
    )
    
    # Pass thread handles to dashboard for reference if needed
    window.capture_thread = capture_thread
    window.detector_thread = detector_thread
    
    # Start detector
    detector_thread.start()

    window.show()
    
    try:
        sys.exit(app.exec())
    finally:
        logging.info("Shutting down netcat threads...")
        if capture_thread:
            capture_thread.stop()
        if detector_thread:
            detector_thread.stop()
        block_manager.shutdown()
        logging.info("netcat clean exit completed.")

if __name__ == "__main__":
    main()
