import sys
import types
from datetime import datetime , timezone

from netwatch.dbalertlog import DbAlertLog
from netwatch.detectors import Alert

class FakeConnection:
    def __init__(self):
        self.executed = []
        self.closed = False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))

    def close(self):
        self.closed = True

def use_fake_psycopg(monkeypatch):
    conn = FakeConnection()
    fake = types.ModuleType("psycopg")
    fake.connect = lambda url, autocommit: conn
    monkeypatch.setitem(sys.modules, "psycopg", fake)
    return conn

def test_creates_table_on_start(monkeypatch):
    conn = use_fake_psycopg(monkeypatch)
    alert = Alert(timestamp=0.0, kind="PORT_SCAN", source_ip="10.0.0.1",
                  target_ip="10.0.0.2",message="test alert")

    with DbAlertLog("postgresql://fake") as log:
        log.write(alert)

    sql, params = conn.executed[1]
    assert sql.startswith("INSERT INTO alerts")
    assert params == (
        datetime(1970,1,1,tzinfo=timezone.utc),
        "PORT_SCAN","10.0.0.1","10.0.0.2","test alert",
    )
    assert conn.closed