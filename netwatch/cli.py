from __future__ import annotations
import argparse
from datetime import datetime
from .capture import live_capture, read_pcap
from .parser import PacketRecord

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

def main(argv=None) -> None:
    parser = argparse.ArgumentParser(
        prog="netwatch",description="Network traffic monitor"
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--pcap", help="read packets from a .pcap file")
    source.add_argument("--live",action="store_true",help="capture live traffic")
    parser.add_argument("--iface",help="network interface for live capture")
    parser.add_argument("--count",type=int,default=0,
                        help="stop after this many packets (0 = no limit)")
    args = parser.parse_args(argv)

    if args.pcap:
        for i, rec in enumerate(read_pcap(args.pcap),start=1):
            print(format_record(rec))
            if args.count and i >= args.count:
                break
    else:
        print("Capturing live traffic....press Ctrl+C to stop")
        try:
            live_capture(lambda rec: print(format_record(rec)),
                         interface=args.iface,count=args.count)
        except KeyboardInterrupt:
            print("\nStopped.")


