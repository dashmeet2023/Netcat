import os
import json
import logging

DEFAULT_CONFIG = {
    "port_scan_threshold": 15,
    "port_scan_window": 5.0,
    "syn_flood_threshold": 100,
    "syn_flood_window": 5.0,
    "icmp_flood_threshold": 50,
    "icmp_flood_window": 5.0,
    "traffic_spike_threshold": 500,
    "traffic_spike_window": 2.0,
    "dns_long_query_threshold": 60,
    "dns_flood_threshold": 40,
    "dns_flood_window": 10.0,
    "whitelist_ips": ["127.0.0.1", "0.0.0.0", "8.8.8.8", "8.8.4.4", "1.1.1.1"],
    "blocked_ips": [],
    "block_mode": "both",  # both, firewall, windivert, none
    "safe_mode": True,     # True = alert/log only, no blocking
    "auto_block_severity": "high",  # none, low, medium, high, critical
    "selected_interface": "",       # Will be filled dynamically by UI or defaults
    "blocked_apps": [],             # DPI blocked apps
    "blocked_domains": [],          # DPI blocked domains
    "use_cpp_dpi_engine": False,    # True = Enable C++ DPI analysis segment handoffs
    "auto_block_enabled": True      # True = Enable automatic IP blocking on threat threshold cross
}

class ConfigManager:
    def __init__(self, config_path="config.json"):
        self.config_path = config_path
        self.config = {}
        self.load()

    def load(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r") as f:
                    loaded_config = json.load(f)
                    # Merge loaded config into default config to handle missing keys
                    self.config = {**DEFAULT_CONFIG, **loaded_config}
                    logging.info(f"Configuration loaded from {self.config_path}")
                    return
            except Exception as e:
                logging.error(f"Error loading configuration, falling back to defaults: {e}")
        
        logging.info("Using default configuration")
        self.config = DEFAULT_CONFIG.copy()
        self.save()

    def save(self):
        try:
            with open(self.config_path, "w") as f:
                json.dump(self.config, f, indent=4)
            logging.info(f"Configuration saved to {self.config_path}")
        except Exception as e:
            logging.error(f"Error saving configuration: {e}")

    def get(self, key, default=None):
        return self.config.get(key, default if default is not None else DEFAULT_CONFIG.get(key))

    def set(self, key, value):
        self.config[key] = value
        self.save()

    def add_to_whitelist(self, ip):
        if ip not in self.config["whitelist_ips"]:
            self.config["whitelist_ips"].append(ip)
            # Remove from blocked list if whitelisted
            if ip in self.config["blocked_ips"]:
                self.config["blocked_ips"].remove(ip)
            self.save()
            return True
        return False

    def remove_from_whitelist(self, ip):
        if ip in self.config["whitelist_ips"]:
            self.config["whitelist_ips"].remove(ip)
            self.save()
            return True
        return False

    def add_to_blocked_ips(self, ip):
        if ip in self.config["whitelist_ips"]:
            logging.warning(f"Attempted to block whitelisted IP: {ip}")
            return False
        if ip not in self.config["blocked_ips"]:
            self.config["blocked_ips"].append(ip)
            self.save()
            return True
        return False

    def remove_from_blocked_ips(self, ip):
        if ip in self.config["blocked_ips"]:
            self.config["blocked_ips"].remove(ip)
            self.save()
            return True
        return False

    def is_whitelisted(self, ip):
        return ip in self.config["whitelist_ips"]

    def is_blocked(self, ip):
        return ip in self.config["blocked_ips"]
