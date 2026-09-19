import logging
import os
import subprocess
import re
import threading
import time

class AppType:
    UNKNOWN = "Unknown"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    TLS = "TLS"
    QUIC = "QUIC"
    GOOGLE = "Google"
    FACEBOOK = "Facebook"
    YOUTUBE = "YouTube"
    TWITTER = "Twitter/X"
    INSTAGRAM = "Instagram"
    NETFLIX = "Netflix"
    AMAZON = "Amazon"
    MICROSOFT = "Microsoft"
    APPLE = "Apple"
    WHATSAPP = "WhatsApp"
    TELEGRAM = "Telegram"
    TIKTOK = "TikTok"
    SPOTIFY = "Spotify"
    ZOOM = "Zoom"
    DISCORD = "Discord"
    GITHUB = "GitHub"
    CLOUDFLARE = "Cloudflare"

def sni_to_app_type(sni: str) -> str:
    if not sni:
        return AppType.UNKNOWN
    
    lower_sni = sni.lower()
    
    # Check for known patterns
    if any(p in lower_sni for p in ["youtube", "ytimg", "youtu.be", "yt3.ggpht"]):
        return AppType.YOUTUBE
    
    # Note: Google must be checked after YouTube since YouTube is owned by Google but we want it specific
    if any(p in lower_sni for p in ["google", "gstatic", "googleapis", "ggpht", "gvt1"]):
        return AppType.GOOGLE
        
    if any(p in lower_sni for p in ["facebook", "fbcdn", "fb.com", "fbsbx", "meta.com"]):
        return AppType.FACEBOOK
        
    if any(p in lower_sni for p in ["instagram", "cdninstagram"]):
        return AppType.INSTAGRAM
        
    if any(p in lower_sni for p in ["whatsapp", "wa.me"]):
        return AppType.WHATSAPP
        
    if any(p in lower_sni for p in ["twitter", "twimg", "x.com", "t.co"]):
        return AppType.TWITTER
        
    if any(p in lower_sni for p in ["netflix", "nflxvideo", "nflximg"]):
        return AppType.NETFLIX
        
    if any(p in lower_sni for p in ["amazon", "amazonaws", "cloudfront", "aws"]):
        return AppType.AMAZON
        
    if any(p in lower_sni for p in ["microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing"]):
        return AppType.MICROSOFT
        
    if any(p in lower_sni for p in ["apple", "icloud", "mzstatic", "itunes"]):
        return AppType.APPLE
        
    if any(p in lower_sni for p in ["telegram", "t.me"]):
        return AppType.TELEGRAM
        
    if any(p in lower_sni for p in ["tiktok", "tiktokcdn", "musical.ly", "bytedance"]):
        return AppType.TIKTOK
        
    if any(p in lower_sni for p in ["spotify", "scdn.co"]):
        return AppType.SPOTIFY
        
    if "zoom" in lower_sni:
        return AppType.ZOOM
        
    if any(p in lower_sni for p in ["discord", "discordapp"]):
        return AppType.DISCORD
        
    if any(p in lower_sni for p in ["github", "githubusercontent"]):
        return AppType.GITHUB
        
    if any(p in lower_sni for p in ["cloudflare", "cf-"]):
        return AppType.CLOUDFLARE
        
    return AppType.HTTPS

class DPIEngine:
    # C++ DPI Integration Cache and subprocess controls
    cpp_flow_cache = {}
    cpp_flow_cache_lock = threading.Lock()
    worker_started = False
    config = None
    block_manager = None
    detector_thread = None
    cpp_process = None
    cpp_stdin_lock = threading.Lock()

    # Pending block events: queued when detector_thread is not yet available.
    # Flushed through trigger_alert() -> evaluate_blocking() once detector_thread is set.
    # NEVER call block_manager.block_ip() directly from here.
    _pending_block_events = []  # list of (ip, reason, arrived_at)
    _pending_lock = threading.Lock()

    @classmethod
    def start_cpp_worker(cls, config):
        cls.config = config
        with cls.cpp_flow_cache_lock:
            if cls.worker_started:
                return
            cls.worker_started = True
            
        def worker_loop():
            workspace_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            exe_path = os.path.join(workspace_dir, "dpi_engine.exe")
            
            warning_logged = False
            
            while True:
                # If disabled, do not launch
                use_cpp = config.get("use_cpp_dpi_engine", False)
                if not use_cpp:
                    time.sleep(1.0)
                    continue
                    
                if not os.path.exists(exe_path):
                    if not warning_logged:
                        logging.warning("C++ DPI engine enabled in config but dpi_engine.exe not found — falling back to Python DPI")
                        warning_logged = True
                    time.sleep(3.0)
                    continue
                else:
                    warning_logged = False
                    
                try:
                    # Dynamically size LBs / FPs threads based on CPU core count (Priority 5)
                    import os as os_module
                    cpu_count = os_module.cpu_count() or 4
                    num_lbs = max(1, cpu_count // 4)
                    fps_per_lb = 2
                    
                    args = [
                        exe_path,
                        "--live",
                        "--lbs", str(num_lbs),
                        "--fps", str(fps_per_lb)
                    ]
                    
                    # Pass blocked rules from config (Priority 4)
                    blocked_apps = config.get("blocked_apps", [])
                    blocked_domains = config.get("blocked_domains", [])
                    for app in blocked_apps:
                        args += ["--block-app", app]
                    for dom in blocked_domains:
                        args += ["--block-domain", dom]
                        
                    logging.info(f"Spawning persistent C++ DPI engine: {' '.join(args)}")
                    
                    cls.cpp_process = subprocess.Popen(
                        args,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL
                    )
                    
                    # Write 24-byte global PCAP header to stdin immediately
                    import struct
                    global_header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
                    with cls.cpp_stdin_lock:
                        cls.cpp_process.stdin.write(global_header)
                        cls.cpp_process.stdin.flush()
                        
                    # Read JSON logs from C++ stdout line-by-line (Priority 3)
                    import json
                    for line in iter(cls.cpp_process.stdout.readline, b""):
                        try:
                            line_str = line.decode("utf-8", errors="ignore").strip()
                            if not line_str:
                                continue
                            if line_str.startswith("{") and line_str.endswith("}"):
                                data = json.loads(line_str)
                                msg_type = data.get("type")
                                if msg_type == "flow":
                                    src_ip = data.get("src_ip")
                                    dst_ip = data.get("dst_ip")
                                    src_port = data.get("src_port")
                                    dst_port = data.get("dst_port")
                                    proto = data.get("protocol")
                                    app = data.get("app")
                                    domain = data.get("domain")
                                    
                                    key = (src_ip, dst_ip, proto, src_port, dst_port)
                                    rev_key = (dst_ip, src_ip, proto, dst_port, src_port)
                                    with cls.cpp_flow_cache_lock:
                                        cls.cpp_flow_cache[key] = (app, domain)
                                        cls.cpp_flow_cache[rev_key] = (app, domain)
                                        
                                elif msg_type == "block":
                                    ip = data.get("ip")
                                    reason = data.get("reason", "C++ rule block")
                                    if cls.detector_thread:
                                        logging.info(f"C++ engine block event received for IP: {ip} | Reason: {reason} | Routing to detector")
                                        cls.detector_thread.trigger_alert(
                                            now=time.time(),
                                            src_ip=ip,
                                            rule="C++ DPI Rule Match",
                                            severity="high",
                                            detail=reason
                                        )
                                    else:
                                        # detector_thread not yet assigned (startup race window).
                                        # Queue the event — it will be flushed through trigger_alert()
                                        # once flush_pending_block_events() is called.
                                        # NEVER call block_manager.block_ip() directly here.
                                        logging.warning(
                                            f"C++ block event for IP {ip} arrived before detector_thread was set. "
                                            f"Queuing for deferred processing through evaluate_blocking(). Reason: {reason}"
                                        )
                                        with cls._pending_lock:
                                            cls._pending_block_events.append((ip, reason, time.time()))
                        except Exception as parse_err:
                            logging.debug(f"Error parsing live C++ JSON output: {parse_err}")
                            
                    # If process exits, wait and try to respawn
                    cls.cpp_process.wait()
                except Exception as run_err:
                    logging.error(f"Error in C++ persistent worker loop: {run_err}")
                
                time.sleep(2.0)
                
        t = threading.Thread(target=worker_loop, daemon=True, name="CppDpiWorker")
        t.start()

    @classmethod
    def flush_pending_block_events(cls):
        """
        Flush any C++ block events that arrived before detector_thread was assigned.
        Must be called after DPIEngine.detector_thread is set.
        All events are routed through trigger_alert() -> evaluate_blocking() so that
        safe_mode, whitelist, and severity gating are always applied.
        Never calls block_manager.block_ip() directly.
        """
        if not cls.detector_thread:
            logging.warning("flush_pending_block_events() called but detector_thread is still None — events remain queued.")
            return

        with cls._pending_lock:
            pending = list(cls._pending_block_events)
            cls._pending_block_events.clear()

        if not pending:
            return

        logging.info(f"Flushing {len(pending)} queued C++ block event(s) through detector evaluate_blocking() gate.")
        for ip, reason, arrived_at in pending:
            delay = time.time() - arrived_at
            logging.info(
                f"[Deferred C++ block] IP={ip} | Reason={reason} | Queued {delay:.3f}s ago "
                f"| Now routing through trigger_alert()"
            )
            cls.detector_thread.trigger_alert(
                now=time.time(),
                src_ip=ip,
                rule="C++ DPI Rule Match",
                severity="high",
                detail=reason
            )

    @classmethod
    def stop_cpp_worker(cls):
        with cls.cpp_stdin_lock:
            if cls.cpp_process:
                logging.info("Terminating persistent C++ DPI engine process...")
                try:
                    cls.cpp_process.stdin.close()
                except Exception:
                    pass
                try:
                    cls.cpp_process.terminate()
                except Exception:
                    pass
                cls.cpp_process = None

    @classmethod
    def feed_scapy_packet(cls, pkt):
        use_cpp = cls.config.get("use_cpp_dpi_engine", False) if cls.config else False
        if not use_cpp or not cls.cpp_process:
            return
            
        try:
            pkt_bytes = bytes(pkt)
            pkt_time = float(pkt.time) if pkt.time else time.time()
            ts_sec = int(pkt_time)
            ts_usec = int((pkt_time - ts_sec) * 1000000)
            incl_len = len(pkt_bytes)
            orig_len = len(pkt_bytes)
            
            import struct
            header_bytes = struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len)
            
            with cls.cpp_stdin_lock:
                if cls.cpp_process and cls.cpp_process.poll() is None:
                    cls.cpp_process.stdin.write(header_bytes)
                    cls.cpp_process.stdin.write(pkt_bytes)
                    cls.cpp_process.stdin.flush()
        except Exception as e:
            logging.debug(f"Failed to feed packet to C++ DPI engine: {e}")

    @classmethod
    def get_cpp_classification(cls, protocol: int, dest_port: int, src_port: int, src_ip: str, dst_ip: str) -> tuple[str | None, str | None]:
        if not src_ip or not dst_ip:
            return None, None
            
        with cls.cpp_flow_cache_lock:
            key = (src_ip, dst_ip, protocol, src_port, dest_port)
            if key in cls.cpp_flow_cache:
                return cls.cpp_flow_cache[key]
            
            rev_key = (dst_ip, src_ip, protocol, dest_port, src_port)
            if rev_key in cls.cpp_flow_cache:
                return cls.cpp_flow_cache[rev_key]
        return None, None

    @classmethod
    def classify_packet(cls, protocol: int, dest_port: int, src_port: int, payload: bytes, src_ip: str = None, dst_ip: str = None) -> tuple[str, str | None]:
        """
        Classifies packet using both Python DPI and C++ DPI signals.
        """
        # 1. Try C++ DPI engine classification if connected and healthy (Priority 4)
        cpp_active = False
        with cls.cpp_stdin_lock:
            if cls.cpp_process and cls.cpp_process.poll() is None:
                cpp_active = True
                
        if cpp_active:
            cpp_app, cpp_domain = cls.get_cpp_classification(protocol, dest_port, src_port, src_ip, dst_ip)
            if cpp_app and cpp_app != AppType.UNKNOWN:
                return f"{cpp_app} (C++)", cpp_domain
            # Skip python classification path entirely if C++ is enabled and active
            return AppType.UNKNOWN, None
            
        # 2. Fall back to Python DPI parser if C++ is unavailable
        return cls._classify_packet_python(protocol, dest_port, src_port, payload)

    @staticmethod
    def is_tls_client_hello(payload: bytes) -> bool:
        # Minimum TLS record: 5 bytes header + 4 bytes handshake header
        if len(payload) < 9:
            return False
            
        # Record Layer: Content Type must be 0x16 = Handshake
        if payload[0] != 0x16:
            return False
            
        # Record Layer: Version (0x0300 to 0x0304)
        version = (payload[1] << 8) | payload[2]
        if version < 0x0300 or version > 0x0304:
            return False
            
        # Record Layer: Record Length
        record_length = (payload[3] << 8) | payload[4]
        if record_length > len(payload) - 5:
            return False
            
        # Handshake Layer: Handshake Type must be 0x01 = Client Hello
        if payload[5] != 0x01:
            return False
            
        return True

    @staticmethod
    def extract_tls_sni(payload: bytes) -> str | None:
        if not DPIEngine.is_tls_client_hello(payload):
            return None
            
        try:
            offset = 5 # skip record header
            
            # Handshake Header: length is 3 bytes (bytes 1-3)
            # handshaketype(1), handshake_length(3)
            offset += 4
            
            # Client Hello Body: Client version (2 bytes)
            offset += 2
            
            # Random: 32 bytes
            offset += 32
            
            # Session ID: length 1 byte, followed by session id
            if offset >= len(payload): return None
            session_id_len = payload[offset]
            offset += 1 + session_id_len
            
            # Cipher Suites: length 2 bytes, followed by suites
            if offset + 2 > len(payload): return None
            cipher_suites_len = (payload[offset] << 8) | payload[offset+1]
            offset += 2 + cipher_suites_len
            
            # Compression Methods: length 1 byte, followed by methods
            if offset >= len(payload): return None
            compression_methods_len = payload[offset]
            offset += 1 + compression_methods_len
            
            # Extensions: length 2 bytes
            if offset + 2 > len(payload): return None
            extensions_len = (payload[offset] << 8) | payload[offset+1]
            offset += 2
            
            extensions_end = offset + extensions_len
            if extensions_end > len(payload):
                extensions_end = len(payload)
                
            # Parse extensions
            while offset + 4 <= extensions_end:
                ext_type = (payload[offset] << 8) | payload[offset+1]
                ext_len = (payload[offset+2] << 8) | payload[offset+3]
                offset += 4
                
                if offset + ext_len > extensions_end:
                    break
                    
                if ext_type == 0x0000: # SNI Extension
                    if ext_len < 5:
                        break
                    
                    sni_list_len = (payload[offset] << 8) | payload[offset+1]
                    if sni_list_len < 3:
                        break
                        
                    sni_type = payload[offset+2]
                    sni_len = (payload[offset+3] << 8) | payload[offset+4]
                    
                    if sni_type != 0x00: # Hostname type
                        break
                    if sni_len > ext_len - 5:
                        break
                        
                    sni_bytes = payload[offset+5 : offset+5+sni_len]
                    return sni_bytes.decode('utf-8', errors='ignore')
                    
                offset += ext_len
        except Exception as e:
            logging.debug(f"Failed parsing TLS ClientHello SNI: {e}")
            
        return None

    @staticmethod
    def is_http_request(payload: bytes) -> bool:
        if len(payload) < 4:
            return False
        # Common HTTP methods
        methods = [b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI"]
        first_4 = payload[:4]
        return first_4 in methods

    @staticmethod
    def extract_http_host(payload: bytes) -> str | None:
        if not DPIEngine.is_http_request(payload):
            return None
            
        try:
            # Search case-insensitive "host:"
            lower_payload = payload.lower()
            idx = lower_payload.find(b"host:")
            if idx == -1:
                return None
                
            start = idx + 5
            # Skip spaces
            while start < len(payload) and (payload[start] == 32 or payload[start] == 9): # space or tab
                start += 1
                
            # Find end of line
            end = start
            while end < len(payload) and payload[end] != 13 and payload[end] != 10: # CR or LF
                end += 1
                
            if end > start:
                host_str = payload[start:end].decode('utf-8', errors='ignore').strip()
                # Remove port if present
                if ":" in host_str:
                    host_str = host_str.split(":")[0]
                return host_str
        except Exception as e:
            logging.debug(f"Failed parsing HTTP Host: {e}")
            
        return None

    @staticmethod
    def is_dns_query(payload: bytes) -> bool:
        if len(payload) < 12:
            return False
            
        # Check QR bit (byte 2, bit 7) - must be 0 for query
        flags = payload[2]
        if (flags & 0x80) != 0:
            return False
            
        # Check QDCOUNT (bytes 4-5) - must be > 0
        qdcount = (payload[4] << 8) | payload[5]
        if qdcount == 0:
            return False
            
        return True

    @staticmethod
    def extract_dns_query(payload: bytes) -> str | None:
        if not DPIEngine.is_dns_query(payload):
            return None
            
        try:
            offset = 12
            labels = []
            
            while offset < len(payload):
                label_len = payload[offset]
                if label_len == 0:
                    break
                if label_len > 63:
                    break
                    
                offset += 1
                if offset + label_len > len(payload):
                    break
                    
                label = payload[offset : offset+label_len].decode('utf-8', errors='ignore')
                labels.append(label)
                offset += label_len
                
            if labels:
                return ".".join(labels)
        except Exception as e:
            logging.debug(f"Failed parsing DNS query: {e}")
            
        return None

    @staticmethod
    def is_quic_initial(payload: bytes) -> bool:
        if len(payload) < 5:
            return False
        # QUIC long header form starts with 1 bit set
        return (payload[0] & 0x80) != 0

    @staticmethod
    def extract_quic_sni(payload: bytes) -> str | None:
        if not DPIEngine.is_quic_initial(payload):
            return None
            
        try:
            # Search for ClientHello signature inside QUIC Initial CRYPTO frame
            # Handshake type 0x01 (ClientHello)
            for i in range(len(payload) - 50):
                if payload[i] == 0x01:
                    # Try to extract SNI as if this was the start of the TLS handshake
                    # (Note: TLS handshake header starts at payload[i], so we simulate record layer header before it)
                    # We create a fake TLS Record header: content_type=0x16, version=0x0303, length = len(payload) - i
                    fake_record_len = len(payload) - i
                    fake_record = bytes([0x16, 0x03, 0x03, (fake_record_len >> 8) & 0xFF, fake_record_len & 0xFF]) + payload[i:]
                    result = DPIEngine.extract_tls_sni(fake_record)
                    if result:
                        return result
        except Exception as e:
            logging.debug(f"Failed parsing QUIC SNI: {e}")
            


    @staticmethod
    def _classify_packet_python(protocol: int, dest_port: int, src_port: int, payload: bytes) -> tuple[str, str | None]:
        if not payload:
            if protocol == 6: # TCP
                if dest_port == 443 or src_port == 443:
                    return AppType.HTTPS, None
                elif dest_port == 80 or src_port == 80:
                    return AppType.HTTP, None
            elif protocol == 17: # UDP
                if dest_port == 53 or src_port == 53:
                    return AppType.DNS, None
                elif dest_port == 443 or src_port == 443:
                    return AppType.QUIC, None
            return AppType.UNKNOWN, None
            
        if protocol == 6: # TCP
            sni = DPIEngine.extract_tls_sni(payload)
            if sni:
                return sni_to_app_type(sni), sni
                
            host = DPIEngine.extract_http_host(payload)
            if host:
                return sni_to_app_type(host), host
                
            if dest_port == 443 or src_port == 443:
                return AppType.HTTPS, None
            elif dest_port == 80 or src_port == 80:
                return AppType.HTTP, None
                
        elif protocol == 17: # UDP
            dns_query = DPIEngine.extract_dns_query(payload)
            if dns_query:
                return AppType.DNS, dns_query
                
            quic_sni = DPIEngine.extract_quic_sni(payload)
            if quic_sni:
                return sni_to_app_type(quic_sni), quic_sni
                
            if dest_port == 53 or src_port == 53:
                return AppType.DNS, None
            elif dest_port == 443 or src_port == 443:
                return AppType.QUIC, None
                
        return AppType.UNKNOWN, None
