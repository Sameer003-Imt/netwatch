from __future__ import annotations
import argparse
from datetime import datetime
from .capture import live_capture, read_pcap
from .parser import PacketRecord
from .stats import TrafficStats
def format_record(rec: PacketRecord) -> str:
    time = datetime.fromtimestamp(rec.timestamp).strftime("%H:%M:%S")
    src = f"{rec.src_ip}:{rec.src_port}" if rec.src_port is not None else rec.src_ip
    dst = f"{rec.dst_ip}:{rec.dst_port}"if rec.dst_port is not None else rec.dst_ip
    line = f"{time} {rec.service:<6} {src} -> {dst} {rec.size} bytes"
    if rec.tcp_flags:
        line += f" flags={rec.tcp_flags}"
    if rec.dns_query:
        line += f" query={rec.dns_query}"
    return line

def format_bytes(num:float) -> str:
    for unit in ("B","KB","MB","GB"):
        if num < 1024 or unit == "GB":
            return f"{num:.1f}{unit}" if unit != "B" else f"{int(num)} B"
        num /= 1024

def print_summary(stats: TrafficStats) -> None:
    print("\n==== NetWatch Summary ====")
    print(f"Packets:        {stats.total_packets}")
    print(f"Data:           {format_bytes(stats.total_bytes)}")
    print(f"Duration:       {stats.duration():.1f}s")
    print(f"Avg packet size:    {stats.average_packet_size():.0f}bytes")
    print(f"Recent rate:        {stats.packets_per_second():.1f}packets/s",
          f"{stats.bits_per_second() / 1000:.1f}kbit/s")
    print("\nTop services:")
    for name, count in stats.top_servcies():
        print(f"{name:<8}{count} packets")

    print("\nTop talkers:")
    for ip, total in stats.top_talkers():
        print(f"{ip:<40}{format_bytes(total)}")

    if stats.dns_queries:
        print("\nTop DNS lookups:")
        for domain, count in stats.top_dns_queries():
            print(f"    {domain:<40}{count}")
    

def main(argv=None) -> None:
    parser = argparse.ArgumentParser(
        prog="netwatch", description="Network traffic monitor"
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--pcap", help="read packets from a .pcap file")
    source.add_argument("--live", action="store_true", help="capture live traffic")
    parser.add_argument("--iface", help="network interface for live capture")
    parser.add_argument("--count", type=int, default=0,
                        help="stop after this many packets (0 = no limit)")
    parser.add_argument("--quiet", action="store_true",
                        help="do not print every packet, only the summary")
    args = parser.parse_args(argv)

    stats = TrafficStats()

    def handle(rec: PacketRecord) -> None:
        stats.update(rec)
        if not args.quiet:
            print(format_record(rec))

    if args.pcap:
        for i, rec in enumerate(read_pcap(args.pcap), start=1):
            handle(rec)
            if args.count and i >= args.count:
                break
    else:
        print("Capturing live traffic... press Ctrl+C to stop.")
        try:
            live_capture(handle, interface=args.iface, count=args.count)
        except KeyboardInterrupt:
            print("\nStopped.")

    print_summary(stats)
    #parser = argparse.ArgumentParser(
      #  prog="netwatch",description="Network traffic monitor"
    #)
    #source = parser.add_mutually_exclusive_group(required=True)
    #source.add_argument("--pcap", help="read packets from a .pcap file")
    #source.add_argument("--live",action="store_true",help="capture live traffic")
    #parser.add_argument("--iface",help="network interface for live capture")
    #parser.add_argument("--count",type=int,default=0,
     #                   help="stop after this many packets (0 = no limit)")
    #args = parser.parse_args(argv)

    ##   for i, rec in enumerate(read_pcap(args.pcap),start=1):
      #      print(format_record(rec))
       #     if args.count and i >= args.count:
        #        break
    #else:
     #   print("Capturing live traffic....press Ctrl+C to stop")
      #  try:
       #     live_capture(lambda rec: print(format_record(rec)),
        #                 interface=args.iface,count=args.count)
        #except KeyboardInterrupt:
         #   print("\nStopped.")


