from rich.console import Console
from netwatch.dashboard import build_dashboard
from netwatch.formatting import format_bytes
from netwatch.parser import PacketRecord
from netwatch.stats import TrafficStats
from netwatch.detectors import Alert
def render_to_text(renderable) -> str:
    console = Console(width=120,record=True,color_system=None)
    console.print(renderable)
    return console.export_text()

def test_format_bytes():
    assert format_bytes(500) == "500 B"
    assert format_bytes(1536) == "1.5 KB"
    assert format_bytes(5*1024*1024) == "5.0 MB"

def test_empty_dashboard_shows_waiting_message():
    text = render_to_text(build_dashboard(TrafficStats(),[]))
    assert "Waiting for packets" in text
    assert "Packets: 0" in text

def test_dashboard_shows_traffic():
    stats = TrafficStats()
    stats.update(PacketRecord(0.0,"10.0.0.1","8.8.8.8","UDP",80,
                              53000,53,dns_query="kau.se"))
    stats.update(PacketRecord(1.0,"10.0.0.1","142.250.74.46","TCP",1500,
                              51000,443))
    text = render_to_text(build_dashboard(stats,["latest packet line"]))
    assert "HTTPS" in text
    assert "DNS" in text
    assert "142.250.74.46" in text
    assert "kau.se" in text
    assert "latest packet line" in text

def test_alerts_box_only_shown_when_there_are_alerts():
    stats = TrafficStats()
    assert "Alerts" not in render_to_text(build_dashboard(stats, []))
    alert = Alert(0.0, "PORT_SCAN", "10.0.0.66","10.0.0.1",
                  "Possible port scan: 10.0.0.66 tried 20 different ports")
    text = render_to_text(build_dashboard(stats,[],[alert]))
    assert "Alerts" in text
    assert "Possible port scan" in text
