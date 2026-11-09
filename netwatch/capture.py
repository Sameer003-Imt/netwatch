from __future__ import annotations
from typing import Callable, Iterator, Optional
from scapy.all import PcapReader, sniff
from .parser import PacketRecord, parse_packet

def read_pcap(path:str) -> Iterator[PacketRecord]:
    with PcapReader(path) as reader:
        for pkt in reader:
            record = parse_packet(pkt)
            if record is not None:
                yield record

def live_capture(
        on_record: Callable[[PacketRecord],None],
        interface: Optional[str] = None,
        count: int = 0,
        timeout: Optional[float] = None,
) -> None:
    def handle(pkt) -> None:
        record = parse_packet(pkt)
        if record is not None:
            on_record(record)
    sniff(iface=interface, prn=handle, store=False, count=count, timeout=timeout)
    