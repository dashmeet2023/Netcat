import threading
import queue
import logging
import time
from scapy.all import sniff, get_working_ifaces, IP, IPv6, TCP, UDP, ICMP, Raw

class CaptureInterface:
    def __init__(self, name, description, ip):
        self.name = name
        self.description = description
        self.ip = ip

    def __str__(self):
        return f"{self.description} ({self.ip}) [{self.name}]"

def list_interfaces():
    """
    Returns a list of CaptureInterface objects representing working network adapters.
    """
    interfaces = []
    try:
        ifaces = get_working_ifaces()
        for iface in ifaces:
            # We prefer adapters with IPs
            ip = iface.ip if iface.ip else "No IP"
            interfaces.append(CaptureInterface(iface.name, iface.description, ip))
    except Exception as e:
        logging.error(f"Error listing network interfaces: {e}")
    return interfaces

class CaptureThread(threading.Thread):
    def __init__(self, interface_name, packet_queue, max_queue_size=10000):
        super().__init__()
        self.interface_name = interface_name
        self.packet_queue = packet_queue
        self.max_queue_size = max_queue_size
        self.daemon = True
        self.running = False
        self.exception = None
        # Rolling pcap buffers
        self.recent_scapy_packets = []
        self.lock = threading.Lock()

    def stop(self):
        self.running = False

    def packet_callback(self, pkt):
        if not self.running:
            return
            
        from netcat.dpi import DPIEngine
        use_cpp = False
        if hasattr(DPIEngine, "config") and DPIEngine.config:
            use_cpp = DPIEngine.config.get("use_cpp_dpi_engine", False)
            
        if not use_cpp:
            with self.lock:
                self.recent_scapy_packets.append(pkt)
                if len(self.recent_scapy_packets) > 1000:
                    self.recent_scapy_packets.pop(0)
        else:
            # Feed raw packet to C++ persistent process stdin
            DPIEngine.feed_scapy_packet(pkt)
        
        # Check if queue is getting full to avoid memory starvation
        if self.packet_queue.qsize() >= self.max_queue_size:
            try:
                # Drop oldest
                self.packet_queue.get_nowait()
            except queue.Empty:
                pass

        try:
            # Normalize packet
            pkt_len = len(pkt)
            timestamp = float(pkt.time) if pkt.time else time.time()
            
            src_ip = None
            dst_ip = None
            protocol = 0
            src_port = 0
            dst_port = 0
            is_syn = False
            is_ack = False
            is_icmp_echo = False
            payload = b""

            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                protocol = pkt[IP].proto
            elif pkt.haslayer(IPv6):
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst
                protocol = pkt[IPv6].nh

            if not src_ip or not dst_ip:
                return # Skip non-IP packets for threat modeling

            if pkt.haslayer(TCP):
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                flags = pkt[TCP].flags
                # Check SYN and ACK flags
                # Scapy flag properties or bitwise checks
                is_syn = bool(flags & 0x02)
                is_ack = bool(flags & 0x10)
            elif pkt.haslayer(UDP):
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
            elif pkt.haslayer(ICMP):
                # ICMP type 8 is echo-request
                is_icmp_echo = (pkt[ICMP].type == 8)

            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)

            packet_data = {
                "timestamp": timestamp,
                "length": pkt_len,
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
            
            self.packet_queue.put(packet_data)
        except Exception as e:
            logging.error(f"Error parsing packet in capture callback: {e}")

    def start_pcap_rotation(self):
        def rotate_loop():
            import os
            from scapy.all import wrpcap
            workspace_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            temp_pcap = os.path.join(workspace_dir, "temp_rotate.pcap")
            
            while self.running:
                time.sleep(3.0)
                packets_to_write = []
                with self.lock:
                    if self.recent_scapy_packets:
                        packets_to_write = list(self.recent_scapy_packets)
                        self.recent_scapy_packets.clear()
                        
                if packets_to_write:
                    try:
                        wrpcap(temp_pcap, packets_to_write)
                    except Exception as e:
                        logging.debug(f"Failed to write rolling pcap: {e}")
                        
        t = threading.Thread(target=rotate_loop, daemon=True, name="PcapRotationThread")
        t.start()

    def run(self):
        self.running = True
        logging.info(f"Starting packet capture on adapter: {self.interface_name}")
        
        # Start background pcap rotation if C++ engine is NOT enabled
        from netcat.dpi import DPIEngine
        use_cpp = False
        if hasattr(DPIEngine, "config") and DPIEngine.config:
            use_cpp = DPIEngine.config.get("use_cpp_dpi_engine", False)
            
        if not use_cpp:
            self.start_pcap_rotation()
        
        def stop_filter(pkt):
            return not self.running

        try:
            # We filter for IP packets to minimize overhead (TCP, UDP, ICMP)
            sniff(
                iface=self.interface_name,
                prn=self.packet_callback,
                filter="ip or ip6",
                store=False,
                stop_filter=stop_filter
            )
        except Exception as e:
            self.exception = e
            self.running = False
            logging.error(f"Error in Scapy sniffing background loop: {e}")
        finally:
            logging.info("Packet capture thread stopped.")
