from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6

WELL_KNOWN_PORTS = {
    20:"FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    3389: "RDP",
}

@dataclass (frozen=True)
class PacketRecord:
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str
    size: int
    src_port: Optional[int] = None
    dst_port: Optional[int]= None
    tcp_flags: Optional[str] = None
    dns_query: Optional[str] = None

    @property
    def service(self) -> str:
        for port in (self.dst_port, self.src_port):
            if port in WELL_KNOWN_PORTS:
                return WELL_KNOWN_PORTS[port]
            return self.protocol

def parse_packet(pkt) -> Optional[PacketRecord]:
    if IP in pkt:
        ip = pkt[IP]
        is_icmp = ICMP in pkt
    elif IPv6 in pkt:
        ip = pkt[IPv6]
        is_icmp = ip.nh == 58
    else: 
        return None

    src_port = dst_port = tcp_flags = None
    if TCP in pkt:
        protocol = "TCP"
        src_port, dst_port = int(pkt[TCP].sport), int(pkt[TCP].dport)
        tcp_flags = str(pkt[TCP].flags)
    elif UDP in pkt:
        protocol = "UDP"
        src_port, dst_port = int(pkt[UDP].sport), int(pkt[UDP].dport)
    elif is_icmp:
        protocol = "ICMP"
    else:
        protocol = "OTHER"

    dns_query = None
    if DNSQR in pkt and DNS in pkt and pkt[DNS].qr == 0:
        qname = pkt[DNSQR].qname
        if isinstance(qname,bytes):
            qname = qname.decode(errors="replace")
        dns_query = qname.rstrip(".")

    return PacketRecord(
        timestamp = float(pkt.time),
        src_ip = str(ip.src),
        dst_ip=str(ip.dst),
        protocol = protocol,
        size = len(pkt),
        src_port = src_port,
        dst_port= dst_port,
        tcp_flags = tcp_flags,
        dns_query=dns_query
    )
