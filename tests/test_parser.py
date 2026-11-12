from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP,TCP,UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP,Ether
from scapy.utils import wrpcap
from netwatch.capture import read_pcap
from netwatch.parser import parse_packet

def test_tcp_packet():
    pkt = Ether() / IP(src="10.0.0.1",dst="10.0.0.2") / TCP(sport=51000,dport=443,flags="S")
    rec = parse_packet(pkt)
    assert rec.protocol == "TCP"
    assert rec.src_ip == "10.0.0.1"
    assert rec.dst_ip == "10.0.0.2"
    assert rec.src_port == 51000
    assert rec.dst_port == 443
    assert rec.tcp_flags == "S"
    assert rec.service == "HTTPS"
    assert rec.size == len(pkt)

def test_udp_dns_query():
    pkt = IP(src="10.0.0.1",dst="8.8.8.8") / UDP(sport=53000,dport=53) / DNS(
        rd=1,qd=DNSQR(qname="example.com")
    )
    rec = parse_packet(pkt)
    assert rec.protocol == "UDP"
    assert rec.service == "DNS"
    assert rec.dns_query == "example.com"

def test_icmp_packet_has_no_ports():
    rec = parse_packet(IP(src="10.0.0.1",dst="10.0.0.2")/ ICMP())
    assert rec.protocol == "ICMP"
    assert rec.src_port is None
    assert rec.dst_port is None

def test_ipv6_packet():
    rec = parse_packet(IPv6(src="fe80::1",dst="fe80::2") / UDP(sport=1234,dport=5678))
    assert rec.protocol == "UDP"
    assert rec.src_ip == "fe80::1"

def test_non_ip_packet_is_ignored():
    assert parse_packet(Ether() / ARP()) is None

def test_read_pcap(tmp_path):
    path = tmp_path / "sample.pcap"
    wrpcap(str(path) , [
        Ether() / IP(src="10.0.0.1",dst="10.0.0.2") / TCP(dport=80),
        Ether() / ARP(),
        Ether() / IP(src="10.0.0.3",dst="10.0.0.4") / UDP(dport=53),
    ])
    records = list(read_pcap(str(path)))
    assert len(records) == 2
    assert [r.service for r in records] == ["HTTP","DNS"]

def test_service_uses_source_port_for_replies():
    rec = parse_packet(IP(src="10.0.0.2",dst="10.0.0.1") / TCP(sport=443,dport=51000,flags="SA"))
    assert rec.service == "HTTPS"

