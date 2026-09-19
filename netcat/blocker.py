import os
import sys
import subprocess
import logging
import threading
import time
import ipaddress

# We will try to import pydivert. If it fails or driver is missing, we fall back.
try:
    import pydivert
    HAS_PYDIVERT = True
except ImportError:
    HAS_PYDIVERT = False
    logging.warning("pydivert module not found. WinDivert backend will be disabled.")

class BlockManager:
    def __init__(self, config_manager, db_manager):
        self.config = config_manager
        self.db = db_manager
        
        # State
        self.active_blocks = {} # ip -> {timestamp, backend, reason, expire_timer}
        self.lock = threading.Lock()
        
        # WinDivert components
        self.windivert_thread = None
        self.windivert_handle = None
        self.windivert_running = False
        
        # Synchronize initially with config's blocked list
        self.load_initial_blocks()

    def load_initial_blocks(self):
        # We start with blocked IPs in config, blocking them via Firewall immediately
        # (Since WinDivert driver is transient, firewall rules persist).
        blocked_ips = self.config.get("blocked_ips", [])
        for ip in blocked_ips:
            if not self.config.is_whitelisted(ip):
                # Apply firewall block
                self._apply_firewall_block(ip)
                self.active_blocks[ip] = {
                    "timestamp": time.time(),
                    "backend": "firewall",
                    "reason": "Restored from configuration persistent blocklist",
                    "expire_timer": None
                }
        
        # Start WinDivert background thread if enabled
        if HAS_PYDIVERT and self.config.get("block_mode") in ["both", "windivert"]:
            self.start_windivert()

    def start_windivert(self):
        with self.lock:
            if self.windivert_running:
                return
            self.windivert_running = True
            self.windivert_thread = threading.Thread(target=self._windivert_loop, daemon=True)
            self.windivert_thread.start()
            logging.info("WinDivert blocking backend thread started.")

    def stop_windivert(self):
        with self.lock:
            self.windivert_running = False
            if self.windivert_handle:
                try:
                    self.windivert_handle.close()
                except Exception:
                    pass
                self.windivert_handle = None
        if self.windivert_thread:
            self.windivert_thread.join(timeout=1.0)
            logging.info("WinDivert blocking backend thread stopped.")

    def _get_windivert_filter(self):
        # Intercept packets to/from blocked IPs
        # If no blocks, filter is "false" so we intercept nothing.
        blocked_ips = [ip for ip, info in self.active_blocks.items() if "windivert" in info["backend"] or "both" in info["backend"]]
        if not blocked_ips:
            return "false"
        
        clauses = []
        for ip in blocked_ips:
            try:
                # Ensure only valid IPs form clauses
                ipaddress.ip_address(ip)
                clauses.append(f"ip.SrcAddr == {ip} or ip.DstAddr == {ip}")
            except ValueError:
                pass
        return " or ".join(clauses)

    def _update_windivert_filter(self):
        if not HAS_PYDIVERT or not self.windivert_running:
            return
            
        # Recreate the WinDivert handle with the new filter
        filter_str = self._get_windivert_filter()
        logging.debug(f"Updating WinDivert filter: {filter_str}")
        
        try:
            # We close the old handle, which will cause the sniffing loop to recreate it
            # with the updated filter string.
            if self.windivert_handle:
                self.windivert_handle.close()
                self.windivert_handle = None
        except Exception as e:
            logging.error(f"Error closing WinDivert handle on filter update: {e}")

    def _windivert_loop(self):
        logging.info("Starting WinDivert packet intercept loop...")
        
        while self.windivert_running:
            filter_str = "false"
            with self.lock:
                filter_str = self._get_windivert_filter()
            
            try:
                # If filter is false, we sleep to avoid polling CPU, but we'll wake up when filter changes
                if filter_str == "false":
                    time.sleep(0.5)
                    continue
                    
                # Open handle
                logging.info(f"Opening WinDivert socket with filter: {filter_str}")
                w = pydivert.WinDivert(filter_str)
                with self.lock:
                    self.windivert_handle = w
                w.open()
                
                # Sniff packets and drop them
                for packet in w:
                    if not self.windivert_running:
                        break
                    # The filter ensures we only intercept packets that should be blocked.
                    # So we simply drop them by NOT calling w.send(packet).
                    # This achieves sub-millisecond, kernel-level drop.
                    logging.debug(f"WinDivert DROPPED packet: {packet.src_addr} -> {packet.dst_addr}")
                    pass
                    
            except Exception as e:
                # WinDivert may raise exception if handle was closed manually (which is how we update the filter)
                # or if it doesn't have privileges.
                if self.windivert_running:
                    logging.error(f"WinDivert loop error: {e}. Re-initializing in 1s...")
                    time.sleep(1.0)
            finally:
                with self.lock:
                    if self.windivert_handle:
                        try:
                            self.windivert_handle.close()
                        except Exception:
                            pass
                        self.windivert_handle = None

    def block_ip(self, ip, duration=None, reason="Manual Block"):
        """
        Blocks an IP address using the configured blocking backend.
        duration: Auto-expiration in seconds. None for persistent.
        """
        # Validate IP format
        try:
            ipaddress.ip_address(ip)
        except ValueError as e:
            logging.error(f"Invalid IP address format for blocking: {ip}. Error: {e}")
            raise ValueError(f"Invalid IP address: {ip}")

        # Whitelist checks
        if self.config.is_whitelisted(ip):
            logging.warning(f"Refusing to block whitelisted IP: {ip}")
            return False

        block_mode = self.config.get("block_mode", "both")
        if block_mode == "none":
            logging.info(f"Block mode is set to NONE. Alert raised but IP {ip} is not blocked.")
            return False

        with self.lock:
            if ip in self.active_blocks:
                logging.info(f"IP {ip} is already blocked.")
                return False

            logging.info(f"Blocking IP: {ip} | Mode: {block_mode} | Duration: {duration}s | Reason: {reason}")
            
            # Apply blocks
            applied_backends = []
            if block_mode in ["both", "firewall"]:
                if self._apply_firewall_block(ip):
                    applied_backends.append("firewall")
            
            if block_mode in ["both", "windivert"] and HAS_PYDIVERT:
                # WinDivert blocks will be activated by updating the filter
                applied_backends.append("windivert")
                
            if not applied_backends:
                logging.error(f"Failed to apply block on any backend for IP: {ip}")
                return False
                
            backend_str = "both" if len(applied_backends) == 2 else applied_backends[0]
            
            # Setup expiration timer
            expire_timer = None
            if duration and duration > 0:
                expire_timer = threading.Timer(duration, self.unblock_ip, args=[ip, "Auto-Expiration"])
                expire_timer.daemon = True
                expire_timer.start()

            self.active_blocks[ip] = {
                "timestamp": time.time(),
                "backend": backend_str,
                "reason": reason,
                "expire_timer": expire_timer
            }
            
            # Save block persistently to config
            self.config.add_to_blocked_ips(ip)
            
            # Log action
            self.db.log_block_action(ip, "blocked", backend_str, reason)

        # Update WinDivert filters outside lock
        if "windivert" in applied_backends or len(applied_backends) == 2:
            self._update_windivert_filter()
            
        return True

    def unblock_ip(self, ip, reason="Manual Unblock"):
        """
        Unblocks an IP address.
        """
        try:
            ipaddress.ip_address(ip)
        except ValueError as e:
            logging.error(f"Invalid IP address format for unblocking: {ip}. Error: {e}")
            raise ValueError(f"Invalid IP address: {ip}")

        with self.lock:
            if ip not in self.active_blocks:
                logging.warning(f"Attempted to unblock non-blocked IP: {ip}")
                return False

            info = self.active_blocks[ip]
            backend = info["backend"]
            logging.info(f"Unblocking IP: {ip} (Blocked by {backend}) | Reason: {reason}")
            
            # Cancel timer if active
            if info["expire_timer"]:
                info["expire_timer"].cancel()

            # Remove blocks
            if "firewall" in backend or "both" in backend:
                self._remove_firewall_block(ip)
            
            del self.active_blocks[ip]
            
            # Remove from config blocked list
            self.config.remove_from_blocked_ips(ip)
            
            # Log action
            self.db.log_block_action(ip, "unblocked", backend, reason)

        # Update WinDivert filters
        if "windivert" in backend or "both" in backend:
            self._update_windivert_filter()
            
        return True

    def _apply_firewall_block(self, ip):
        try:
            # Block Inbound
            cmd_in = ["netsh", "advfirewall", "firewall", "add", "rule",
                      f"name=NetCat_Block_{ip}_In", "dir=in", "action=block",
                      f"remoteip={ip}", "protocol=any"]
            # Block Outbound
            cmd_out = ["netsh", "advfirewall", "firewall", "add", "rule",
                       f"name=NetCat_Block_{ip}_Out", "dir=out", "action=block",
                       f"remoteip={ip}", "protocol=any"]
            
            subprocess.run(cmd_in, shell=False, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(cmd_out, shell=False, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to apply Windows Firewall rules for IP {ip}: {e}")
            return False

    def _remove_firewall_block(self, ip):
        try:
            cmd_in = ["netsh", "advfirewall", "firewall", "delete", "rule",
                      f"name=NetCat_Block_{ip}_In"]
            cmd_out = ["netsh", "advfirewall", "firewall", "delete", "rule",
                       f"name=NetCat_Block_{ip}_Out"]
            subprocess.run(cmd_in, shell=False, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(cmd_out, shell=False, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to remove Windows Firewall rules for IP {ip}: {e}")
            return False

    def get_active_blocks(self):
        with self.lock:
            # Return copy of blocks dictionary
            return {ip: {
                "timestamp": info["timestamp"],
                "backend": info["backend"],
                "reason": info["reason"]
            } for ip, info in self.active_blocks.items()}

    def clean_all_blocks(self):
        """
        Cleans up all blocks (called on manual master reset).
        """
        logging.info("Cleaning up all active blocks...")
        ips = list(self.active_blocks.keys())
        for ip in ips:
            self.unblock_ip(ip, "Master Reset Clean")
        self.stop_windivert()

    def shutdown(self):
        """
        Gracefully shut down the blocking backend (stops WinDivert thread and closes handle)
        without clearing persistent firewall blocks.
        """
        logging.info("Shutting down blocking backend cleanly...")
        self.stop_windivert()
