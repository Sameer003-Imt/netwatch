from __future__ import annotations
from collections import Counter, deque
from typing import Deque, List, Optional, Tuple
from .parser import PacketRecord

class TrafficStats:
    def __init__ (self, window_seconds: float = 10.0) -> None:
        self.window_seconds = window_seconds

        self.total_packets = 0
        self.total_bytes = 0
        self.first_seen: Optional[float] = None
        self.last_seen: Optional[float]= None

        self.service_counts: Counter = Counter()
        self.bytes_by_ip: Counter = Counter()
        self.dns_queries: Counter = Counter()
        self._recent: Deque[Tuple[float,int]] = deque()

    def update(self,rec: PacketRecord) -> None:
        self.total_packets += 1
        self.total_bytes += rec.size

        if self.first_seen is None:
            self.first_seen = rec.timestamp
        self.last_seen = rec.timestamp

        self.service_counts[rec.service] += 1
        self.bytes_by_ip[rec.src_ip] += rec.size
        self.bytes_by_ip[rec.dst_ip] += rec.size
        if rec.dns_query:
            self.dns_queries[rec.dns_query] += 1
        self._recent.append((rec.timestamp, rec.size))
        self._drop_old_packets()

    def _drop_old_packets(self) -> None:
        cutoff = self.last_seen - self.window_seconds
        while self._recent and self._recent[0][0] < cutoff:
            self._recent.popleft()

    def packets_per_second(self)-> float:
        return len(self._recent) / self.window_seconds

    def bits_per_second(self) -> float:
        recent_bytes = sum(size for _, size in self._recent)
        return recent_bytes * 8 / self.window_seconds

    def duration(self) -> float:
        if self.first_seen is None:
            return 0.0
        return self.last_seen - self.first_seen

    def average_packet_size(self) -> float:
        if self.total_packets == 0:
            return 0.0
        return self.total_bytes / self.total_packets

    def top_servcies(self, n: int =5) -> List[Tuple[str,int]]:
        return self.service_counts.most_common(n)

    def top_talkers(self, n: int =5) -> List[Tuple[str, int]]:
        return self.bytes_by_ip.most_common(n)

    def top_dns_queries(self, n:int =5) -> List[Tuple[str,int]]:
        return self.dns_queries.most_common(n)

    