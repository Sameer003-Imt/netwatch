import pytest

from netwatch.parser import PacketRecord
from netwatch.stats import TrafficStats

def make_record(timestamp, src="10.0.0.1",dst="10.0.0.2",size=100,
                protocol="TCP",dst_port=443,dns_query=None):
    return PacketRecord(timestamp=timestamp, src_ip=src, dst_ip=dst,
                        protocol=protocol, size=size,src_port=50000,
                        dst_port=dst_port,dns_query=dns_query)

def test_empty_stats():
    stats = TrafficStats()
    assert stats.total_packets == 0
    assert stats.duration() == 0.0
    assert stats.average_packet_size() == 0.0
    assert stats.top_servcies() == []

def test_tools_and_average():
    stats = TrafficStats()
    stats.update(make_record(0.0,size=100))
    stats.update(make_record(1.0,size=300))
    assert stats.total_packets == 2
    assert stats.total_bytes == 400
    assert stats.average_packet_size() == 200
    assert stats.duration() == 1.0

def test_top_services():
    stats = TrafficStats()
    for t in range(3):
        stats.update(make_record(t,dst_port=443))
    stats.update(make_record(3, protocol="UDP", dst_port=53))
    assert stats.top_servcies() == [("HTTPS",3),("DNS",1)]

def test_top_talkers_counts_both_directions():
    stats = TrafficStats()
    stats.update(make_record(0, src="10.0.0.1", dst="8.8.8.8",size=100))
    stats.update(make_record(1,src="8.8.8.8",dst="10.0.0.1",size=500))
    stats.update(make_record(2,src="10.0.0.5",dst="1.1.1.1",size=50))
    top = stats.top_talkers(2)
    assert top == [("10.0.0.1",600),("8.8.8.8",600)]

def test_dns_queries():
    stats = TrafficStats()
    stats.update(make_record(0,protocol="UDP",dst_port=53,dns_query="google.com"))
    stats.update(make_record(1,protocol="UDP",dst_port=53,dns_query="google.com"))
    stats.update(make_record(2,protocol="UDP",dst_port=53,dns_query="kau.se"))
    assert stats.top_dns_queries() == [("google.com",2),("kau.se",1)]

def test_rates_only_count_recent_packets():
    stats = TrafficStats(window_seconds=10)
    stats.update(make_record(0.0,size=1000))
    for t in range(20,30):
        stats.update(make_record(float(t),size=125))
    assert stats.packets_per_second() == pytest.approx(1.0)
    assert stats.bits_per_second() == pytest.approx(1000.0)


