from __future__ import annotations
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict,List, Optional, Set, Tuple
from .parser import PacketRecord
import math


@dataclass(frozen=True)
class Alert:
    timestamp: float
    kind: str
    source_ip: str
    target_ip: str
    message: str

def is_connection_attempt(rec: PacketRecord) -> bool:
    return(
        rec.protocol == "TCP"
        and rec.tcp_flags is not None
        and "S" in rec.tcp_flags
        and "A" not in rec.tcp_flags
    )

class PortScanDetector:
    def __init__(self,port_threshold:int=15,window_seconds: float=5.0,
                 cooldown_seconds: float = 60.0) -> None:
        self.port_threshold = port_threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self._attempts: Dict[Tuple[str, str], Deque[Tuple[float,int]]] = defaultdict(deque)
        self._last_alert: Dict[Tuple[str, str], float] = {}

    def check(self, rec:PacketRecord) -> Optional[Alert]:
        if not is_connection_attempt(rec) or rec.dst_port is None:
            return None
        key = (rec.src_ip, rec.dst_ip)
        attempts = self._attempts[key]
        attempts.append((rec.timestamp, rec.dst_port))
        cutoff = rec.timestamp - self.window_seconds
        while attempts and attempts[0][0] < cutoff:
            attempts.popleft()

        ports = {port for _, port in attempts}
        if len(ports) < self.port_threshold:
            return None
        
        last = self._last_alert.get(key)
        if last is not None and rec.timestamp - last < self.cooldown_seconds:
            return None
        self._last_alert[key] = rec.timestamp 
        return Alert(
            timestamp=rec.timestamp,
            kind="PORT_SCAN",
            source_ip=rec.src_ip,
            target_ip=rec.dst_ip,
            message=(f"Possible port scan: {rec.src_ip} tried {len(ports)}"
                     f"different ports on {rec.dst_ip} within"
                     f"{self.window_seconds: .0f}s"),
        )

class TrafficSpikeDetector:
    def __init__(self, multiplier: float=5.0, min_packets:int=100,
                 history_seconds: int=30, min_history: int=10,
                 cooldown_seconds: float=60.0) -> None:
        self.multiplier= multiplier
        self.min_packets = min_packets
        self.min_history = min_history
        self.cooldown_seconds = cooldown_seconds

        self._history: Deque[int] = deque(maxlen=history_seconds)
        self._current_second: Optional[int] = None
        self._current_count = 0
        self._last_alert: Optional[float] = None

    def check(self, rec: PacketRecord) -> Optional[Alert]:
        second = int(rec.timestamp)
        if self._current_second is None:
            self._current_second = second

        alert = None
        if second > self._current_second:
            alert = self._finish_second()
            empty_seconds = second - self._current_second-1
            for _ in range(min(empty_seconds,self._history.maxlen)):
                self._history.append(0)
            self._current_second = second
            self._current_count = 0

        self._current_count += 1
        return alert

    def _finish_second(self) -> Optional[Alert]:
        count = self._current_count
        alert = None
        if len(self._history) >= self.min_history:
            average = sum(self._history) / len(self._history)
            limit = max(self.min_packets, average * self.multiplier)
            in_cooldown = (self._last_alert is not None and
                           self._current_second - self._last_alert < self.cooldown_seconds)
            if count > limit and not in_cooldown:
                self._last_alert = self._current_second
                alert = Alert(
                    timestamp=float(self._current_second),
                    kind="TRAFFIC_SPIKE",
                    source_ip="*",
                    target_ip="*",
                    message=(f"Traffic spike: {count} packets in one second "
                             f"(normal is about {average:.0f} per second)"),
                )
        self._history.append(count)
        return alert

        

def shannon_entropy(text:str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c/n) *math.log2(c/n) for c in counts.values())

class SuspiciousDnsDetector:
    def __init__(self,max_label_length: int=40,entropy_threshold:float=4.0,
                 min_entropy_length:int=20) -> None:
        self.max_label_length = max_label_length
        self.entropy_threshold = entropy_threshold
        self.min_entropy_length = min_entropy_length
        self._already_alerted: Set[str] = set()

    def reasons(self, domain:str) -> List[str]:
        found = []
        for label in domain.split("."):
            if len(label) > self.max_label_length:
                found.append(f"very long part({len(label)} characters)")
            elif (len(label) >= self.min_entropy_length and 
                  shannon_entropy(label) >= self.entropy_threshold):
                found.append(f"random-looking part(entropy{shannon_entropy(label):.1f})")
        return found

    def check(self, rec:PacketRecord) -> Optional[Alert]:
        domain = rec.dns_query
        if not domain or domain in self._already_alerted:
            return None
        found = self.reasons(domain)
        if not found:
            return None
        self._already_alerted.add(domain)
        return Alert(
            timestamp=rec.timestamp,
            kind="SUSPICIOUS_DNS",
            source_ip=rec.src_ip,
            target_ip=rec.dst_ip,
            message=f"Suspicious DNS lookup: {domain} ({', '.join(found)})",
        )

    