import os

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, wrpcap

ME = "192.168.1.10"          
WEBSITE = "93.184.216.34"    
DNS_SERVER = "192.168.1.1"
FLOODER = "192.168.1.77"     
SCANNER = "192.168.1.66"     


def make_packets():
    packets = []
    t = 1_700_000_000.0  

    def add(pkt, gap):
        """Save a packet with the current time, then move the clock on by `gap`."""
        nonlocal t
        pkt.time = t
        packets.append(pkt)
        t += gap

    def dns_lookup(name):
        add(Ether() / IP(src=ME, dst=DNS_SERVER) / UDP(sport=53000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=name)), gap=0.2)

    
    dns_lookup("example.com")
    for i in range(100):
        add(Ether() / IP(src=ME, dst=WEBSITE) / TCP(sport=50000, dport=443, flags="PA"),
            gap=0.2)

   
    dns_lookup("aGVsbG8gd29ybGQgdGhpcyBpcyBzZWNyZXQgZGF0YQ.tunnel.example")
    dns_lookup("x7k2p9q4m8z1w5r3t6y0b2.com")

   
    for i in range(400):
        add(Ether() / IP(src=FLOODER, dst=ME) / UDP(sport=40000, dport=9999), gap=0.002)

    
    t += 1.0
    for port in range(1, 101):
        add(Ether() / IP(src=SCANNER, dst=ME) / TCP(sport=45000, dport=port, flags="S"),
            gap=0.02)

    return packets


def main():
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", "demo.pcap")
    packets = make_packets()
    wrpcap(path, packets)
    print(f"Wrote {len(packets)} packets to {path}")


if __name__ == "__main__":
    main()