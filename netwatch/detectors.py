from __future__ import annotations
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Optional, Tuple
from .parser import PacketRecord

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

    