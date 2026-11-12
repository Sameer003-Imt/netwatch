import os
from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, wrpcap

ME = "192.168.1.10"
WEBSITE = "93.184.216.34"
DNS_SERVER = "192.168.1.1"
SCANNER = "192.168.1.66"

def make_packets():
    packets = []
    t = 1_700_000_000.0

    def add(pkt):
        nonlocal t
        pkt.time = t
        packets.append(pkt)
        t += 0.05

    add(Ether() / IP(src=ME, dst=DNS_SERVER) / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com")))
    for i in range(30):
        add(Ether() / IP(src=ME, dst=WEBSITE) / TCP(sport=50000 + i, dport=443, flags="S"))
        add(Ether() / IP(src=WEBSITE, dst=ME) / TCP(sport=443, dport=50000 + i, flags="SA"))

    for port in range(1,101):
        add(Ether() / IP(src=SCANNER, dst=ME) / TCP(sport=45000, dport=port,flags="S"))
    return packets

def main():
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", "port_scan.pcap")
    packets = make_packets()
    wrpcap(path, packets)
    print(f"Wrote {len(packets)} packets to {path}")

if __name__ == "__main__":
    main()
    