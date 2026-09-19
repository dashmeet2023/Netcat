import sys, os, time, logging
sys.path.insert(0, 'd:/Netcat')
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

from netcat.detector import ThreatEvent
from netcat.report_generator import ReportGenerator
from netcat.database import DatabaseManager

db = DatabaseManager('netcat.db')
ReportGenerator.db_manager = db

# Use the real 6994-byte test pcap (real captured traffic, not empty)
pcap_path = 'd:/Netcat/Packet_analyzer_extracted/Packet_analyzer-main/test_dpi.pcap'
alert_id = 100

event = ThreatEvent(
    timestamp=time.strftime('%Y-%m-%dT%H:%M:%S'),
    src_ip='192.168.1.50',
    rule='SYN Flood Alert',
    severity='high',
    detail='Port scan detected on multiple ports',
    alert_id=alert_id
)

print('=== Triggering generate_report() with real pcap and C++ engine present ===')
ReportGenerator.generate_report(alert_id, event, pcap_path)
time.sleep(1)

# Verify DB
res = db.get_threat_analysis(alert_id)
print()
print('=== DB threat_analysis entry for alert', alert_id, '===')
import json
if res:
    parsed = json.loads(res)
    print(json.dumps(parsed['summary'], indent=2))
    flows = parsed['flows']
    packets = parsed['packets']
    print('  flows count:', len(flows))
    print('  packets count:', len(packets))
else:
    print('NONE - DB entry missing')

# Verify files
reports_dir = 'd:/Netcat/reports'
md_path = os.path.join(reports_dir, str(alert_id) + '.md')
pdf_path = os.path.join(reports_dir, str(alert_id) + '.pdf')
print()
md_exists = os.path.exists(md_path)
pdf_exists = os.path.exists(pdf_path)
md_size = os.path.getsize(md_path) if md_exists else 0
pdf_size = os.path.getsize(pdf_path) if pdf_exists else 0
print('reports/' + str(alert_id) + '.md exists:', md_exists, '| size:', md_size, 'bytes')
print('reports/' + str(alert_id) + '.pdf exists:', pdf_exists, '| size:', pdf_size, 'bytes')
if md_exists:
    print()
    print('=== Markdown content ===')
    with open(md_path) as f:
        print(f.read())
