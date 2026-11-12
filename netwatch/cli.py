from __future__ import annotations
import argparse
from contextlib import nullcontext
from datetime import datetime
from .capture import live_capture, read_pcap
from .detectors import (Alert, PortScanDetector, SuspiciousDnsDetector, TrafficSpikeDetector)
from .formatting import format_bytes, format_time
from .parser import PacketRecord
from .dashboard import Dashboard
from .stats import TrafficStats
from .alertlog import AlertLog
import os
import argparse


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

def format_alert(alert: Alert) -> str:
    return f"! ! ALERT {format_time(alert.timestamp)} {alert.kind}:{alert.message}"

def print_summary(stats: TrafficStats, alerts) -> None:
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
        print(f"\nAlerts:{len(alerts)}")
        for alert in alerts:
            print("" + format_alert(alert))
    

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
    parser.add_argument("--dashboard", action="store_true",
                        help="show a live dashboard instead of packet lines")
    parser.add_argument("--alert-log", metavar="FILE",
                        help="save alerts to this file (JSON Lines, e.g. alerts.jsonl)")
    args = parser.parse_args(argv)

    if args.pcap and not os.path.exists(args.pcap):
        parser.error(f"file not found: {args.pcap}")

    stats = TrafficStats()
    
    detectors = [PortScanDetector(), TrafficSpikeDetector(), SuspiciousDnsDetector()]
    alerts = []
    if args.live and not args.dashboard:
        print("Capturing live traffic... press Ctrl+C to stop.")

    
    dashboard_cm = Dashboard(stats) if args.dashboard else nullcontext()
    log_cm = AlertLog(args.alert_log) if args.alert_log else nullcontext()

    with dashboard_cm as dashboard, log_cm as alert_log:

        def handle(rec: PacketRecord) -> None:
            stats.update(rec)

            new_alerts = []
            for detector in detectors:
                alert = detector.check(rec)
                if alert is not None:
                    new_alerts.append(alert)
            alerts.extend(new_alerts)

            if alert_log is not None:
                for alert in new_alerts:
                    alert_log.write(alert)

            if dashboard is not None:
                dashboard.add(format_record(rec))
                for alert in new_alerts:
                    dashboard.add_alert(alert)
            else:
                if not args.quiet:
                    print(format_record(rec))
                for alert in new_alerts:
                    print(format_alert(alert))  

        try:
            if args.pcap:
                for i, rec in enumerate(read_pcap(args.pcap), start=1):
                    handle(rec)
                    if args.count and i >= args.count:
                        break
            else:
                live_capture(handle, interface=args.iface, count=args.count)
        except KeyboardInterrupt:
            pass  

    if not args.dashboard:
        print_summary(stats, alerts)
 #---------------------------#####   
    #parser = argparse.ArgumentParser(
     #   prog="netwatch", description="Network traffic monitor"
    #)
    ##source = parser.add_mutually_exclusive_group(required=True)
    #source.add_argument("--pcap", help="read packets from a .pcap file")
    #source.add_argument("--live", action="store_true", help="capture live traffic")
    #parser.add_argument("--iface", help="network interface for live capture")
    #parser.add_argument("--count", type=int, default=0,
     #                   help="stop after this many packets (0 = no limit)")
    #parser.add_argument("--quiet", action="store_true",
     #                   help="do not print every packet, only the summary")
    #parser.add_argument("--dashboard", action="store_true",
     #                   help="show a live dashboard instead of packet lines")
    #args = parser.parse_args(argv)

    #stats = TrafficStats()
    ##detector = PortScanDetector()
    #alerts = []
    ##   print("Capturing live traffic... press Ctrl+C to stop.")

   
    #with Dashboard(stats) if args.dashboard else nullcontext() as dashboard:

     ##      stats.update(rec)
        ##   if alert is not None:
          #      alerts.append(alert)

           # if dashboard is not None:
            #    dashboard.add(format_record(rec))
             #   if alert is not None:
              #      dashboard.add_alert(alert)
            #else:
             #   if not args.quiet:
              #      print(format_record(rec))
               # if alert is not None:
                #    print(format_alert(alert))
           

        #try:
         #   if args.pcap:
          #      for i, rec in enumerate(read_pcap(args.pcap), start=1):
           #         handle(rec)
              #      if args.count and i >= args.count:
               #         break
            #else:
             #   live_capture(handle, interface=args.iface, count=args.count)
        #except KeyboardInterrupt:
         #   pass  

    #if not args.dashboard:
     #   print_summary(stats, alerts)

#----------------------------------------#########
    #parser = argparse.ArgumentParser(
     #   prog="netwatch", description="Network traffic monitor"
    #)
    #source = parser.add_mutually_exclusive_group(required=True)
    ##source.add_argument("--pcap", help="read packets from a .pcap file")
    #source.add_argument("--live", action="store_true", help="capture live traffic")
    #parser.add_argument("--iface", help="network interface for live capture")
    #parser.add_argument("--count", type=int, default=0,
     #                   help="stop after this many packets (0 = no limit)")
    ##                   help="do not print every packet, only the summary")
    #args = parser.parse_args(argv)

    #stats = TrafficStats()

    ##   stats.update(rec)
      #  if not args.quiet:
       #     print(format_record(rec))

    #if args.pcap:
     ##      handle(rec)
       #     if args.count and i >= args.count:
        #        break
    #else:
     #   print("Capturing live traffic... press Ctrl+C to stop.")
      #  try:
       #     live_capture(handle, interface=args.iface, count=args.count)
       # except KeyboardInterrupt:
        #    print("\nStopped.")

    #print_summary(stats)

#-----------------------------------------###
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


