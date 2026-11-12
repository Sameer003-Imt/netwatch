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

