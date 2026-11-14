from datetime import datetime, timezone
from .detectors import Alert

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    time TIMESTAMPTZ NOT NULL,
    kind TEXT NOT NULL,
    source_ip TEXT,
    target_ip TEXT,
    message TEXT NOT NULL
)
"""

class DbAlertLog:
    def __init__(self,url: str) -> None:
        import psycopg
        self._conn = psycopg.connect(url, autocommit=True)
        self._conn.execute(CREATE_TABLE)

    def write(self, alert: Alert) -> None:
        self._conn.execute(
            "INSERT INTO alerts (time , kind , source_ip , target_ip , message)"
            "VALUES (%s , %s , %s , %s , %s)",
            (
                datetime.fromtimestamp(alert.timestamp, tz=timezone.utc),
                alert.kind,
                alert.source_ip,
                alert.target_ip,
                alert.message,
            ),
        )
    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> None:
        return self

    def __exit__(self, *exec) -> None:
        self.close()

    