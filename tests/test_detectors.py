from netwatch.detectors import PortScanDetector, is_connection_attempt
from netwatch.parser import PacketRecord

def syn(timestamp, dst_port, src="192.168.1.66",dst="192.168.1.10",flags="S"):
    return PacketRecord(timestamp=timestamp, src_ip=src,dst_ip=dst,
                        protocol="TCP",size=60,src_port=40000,
                        dst_port=dst_port,tcp_flags=flags)

def run(detector, records):
    alerts = []
    for rec in records:
        alert = detector.check(rec)
        if alert is not None:
            alerts.append(alert)
    return alerts

def test_connection_attempt_is_syn_without_ack():
    assert is_connection_attempt(syn(0,80,flags="S"))
    assert not is_connection_attempt(syn(0,80,flags="SA"))
    assert not is_connection_attempt(syn(0,80,flags="A"))

def test_scan_of_many_ports_raises_alert():
    detector = PortScanDetector(port_threshold=15,window_seconds=5)
    scan = [syn(i * 0.01, port) for i, port in enumerate(range(1,21))]
    alerts = run(detector, scan)
    assert len(alerts) == 1
    assert alerts[0].kind == "PORT_SCAN"
    assert alerts[0].source_ip == "192.168.1.66"
    assert alerts[0].target_ip == "192.168.1.10"

def test_many_connections_to_same_port_is_not_a_scan():
    detector = PortScanDetector(port_threshold=15, window_seconds=5)
    normal = [syn(i * 0.01, 443) for i in range (100)]
    assert run(detector, normal) == []


def test_slow_scan_below_rate_is_not_detected():
    detector = PortScanDetector(port_threshold=15,window_seconds=5)
    slow = [syn(float(i), port) for i, port in enumerate(range(1,31))]
    assert run(detector, slow) == []

def test_replies_ignored():
    detector = PortScanDetector(port_threshold=15, window_seconds=5)
    replies = [syn(i * 0.01, port, flags="SA") for i, port in enumerate(range(1,50))]
    assert run(detector, replies) == []

def test_cooldown_prevents_repeated_alerts():
    detector = PortScanDetector(port_threshold=15, window_seconds=5, cooldown_seconds=60)
    first_scan = [syn(i * 0.01, port) for i, port in enumerate(range(1,101))]
    assert len(run(detector, first_scan)) == 1
    later_scan = [syn(100 + i * 0.01, port) for i, port in enumerate(range(1,21))]
    assert len(run(detector, later_scan)) == 1

def test_different_attackers_are_tracked_seperately():
    detector = PortScanDetector(port_threshold=15, window_seconds=5)
    records = []
    for i, port in enumerate(range(1,11)):
        records.append(syn(i*0.01,port,src="10.0.0.1"))
        records.append(syn(i * 0.01, port, src="10.0.0.2"))
    assert run(detector, records) == []

from netwatch.detectors import SuspiciousDnsDetector, TrafficSpikeDetector, shannon_entropy

def packets_at(second, count, src="10.0.0.1"):
    return[PacketRecord(timestamp=second + i / count, src_ip=src, dst_ip="10.0.0.2",
                        protocol="UDP",size=100,src_port=1000,dst_port=2000)
                        for i in range(count)]
def steady_traffic(seconds, per_second):
    records = []
    for s in range(seconds):
        records += packets_at(s,per_second)
    return records

def test_steady_traffic_has_no_spike():
    detector = TrafficSpikeDetector()
    assert run(detector, steady_traffic(30,20)) == []

def test_sudden_burst_is_a_spike():
    detector = TrafficSpikeDetector(multiplier=5,min_packets=100)
    records = steady_traffic(20,10)
    records += packets_at(20,500)
    records += packets_at(21,10)
    alerts = run(detector, records)
    assert len(alerts) == 1
    assert alerts[0].kind == "TRAFFIC_SPIKE"
    assert "500 packets" in alerts[0].message

def test_small_burst_below_minimum_is_ignored():
    detector = TrafficSpikeDetector(multiplier=5,min_packets=100)
    records = steady_traffic(20,2) + packets_at(20,50) + packets_at(21,2)
    assert run(detector, records) == []

def test_no_alert_before_enough_history():
    detector = TrafficSpikeDetector(min_history=10)
    records = steady_traffic(3,10) + packets_at(3,500) + packets_at(4,10)
    assert run(detector, records) == []

def dns(domain, timestamp=0.0):
    return PacketRecord(timestamp=timestamp, src_ip="10.0.0.1",dst_ip="8.8.8.8",
                        protocol="UDP",size=80,src_port=53000,dst_port=53,
                        dns_query=domain)

def test_entropy():
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("ab") == 1.0
    assert shannon_entropy ("x7k2p9q4m8z1w5r3t6y0b2") > 4.0
    assert shannon_entropy("google") < 3.0

def test_normal_domains_are_fine():
    detector = SuspiciousDnsDetector()
    normal = ["www.kau.se","google.com","fonts.googleapis.com",
              "r3---sn-uxax4vopj5qx.googlevideo.com","login.microsoftonline.com"]
    assert run(detector, [dns(d) for d in normal]) == []

def test_very_long_label_is_suspicious():
    detector = SuspiciousDnsDetector()
    tunnel = "aGVsbG8gd29ybGQgdGhpcyBpcyBzZWNyZXQgZGF0YQ.tunnel.example"
    alerts = run(detector, [dns(tunnel)])
    assert len(alerts) == 1
    assert alerts[0].kind == "SUSPICIOUS_DNS"
    assert "very long" in alerts[0].message

def test_random_looking_domain_is_suspicious():
    detector = SuspiciousDnsDetector()
    alerts = run(detector,[dns("x7k2p9q4m8z1w5r3t6y0b2.com")])
    assert len(alerts) == 1
    assert "random-looking" in alerts[0].message

def test_same_domain_is_reported_only_once():
    detector = SuspiciousDnsDetector()
    lookups = [dns("x7k2p9q4m8z1w5r3t6y0b2.com",t) for t in range(5)]
    assert len(run(detector,lookups)) == 1
    
