from __future__ import annotations
import json
from dataclasses import asdict
from datetime import datetime, timezone
from typing import List
from .detectors import Alert

class AlertLog:
    def __init__(self,path:str) -> None:
        self.path = path
        self._file = open(path,"a",encoding="utf-8")
    def write(self, alert: Alert) -> None:
        record = asdict(alert)
        record["time"] = datetime.fromtimestamp(alert.timestamp, tz=timezone.utc).isoformat()
        self._file.write(json.dumps(record) + "\n")
        self._file.flush()
    def close(self) -> None:
        self._file.close()
    def __enter__(self) -> "AlertLog":
        return self
    def __exit__(self,*exc) -> None:
        self.close()

def read_alert_log(path: str) -> List[dict]:
    with open(path, encoding="utf-8") as f:
        return[json.loads(line) for line in f if line.strip()]

