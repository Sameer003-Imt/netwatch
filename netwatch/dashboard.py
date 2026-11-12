from __future__ import annotations
import time
from collections import deque
from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from .detectors import Alert
from .formatting import format_bytes, format_time
from .stats import TrafficStats

def build_overview(stats: TrafficStats) -> Panel:
    grid = Table.grid(expand=True)
    for _ in range(3):
        grid.add_column(ratio=1)
    grid.add_row(
        f"[bold]Packets:[/] {stats.total_packets}",
        f"[bold]Data:[/] {format_bytes(stats.total_bytes)}",
        f"[bold]Duration:[/] {stats.duration():.1f} s",
    )
    grid.add_row(
        f"[bold]Rate:[/] {stats.packets_per_second():.1f} pkt/s",
        f"[bold]Bandwidth:[/] {stats.bits_per_second() / 1000:.1f} kbit/s",
        f"[bold]Avg size:[/] {stats.average_packet_size():.0f} B",
    )
    return Panel(grid, title="Netwatch",border_style="cyan")

def build_services_table(stats: TrafficStats) -> Table:
    table = Table(title="Top services",expand=True)
    table.add_column("Service")
    table.add_column("Packets",justify="right")
    table.add_column("Share",justify="right")
    for name, count in stats.top_servcies():
        share = 100 * count / stats.total_packets
        table.add_row(name,str(count),f"{share:.0f}%")
    return table

def build_talkers_table(stats: TrafficStats) -> Table:
    table = Table(title="Top Talkers",expand=True)
    table.add_column("IP addresses")
    table.add_column("Data",justify="right")
    for ip, total in stats.top_talkers():
        table.add_row(ip, format_bytes(total))
    return table

def build_dns_table(stats: TrafficStats) -> Table:
    table = Table(title="Top DNS Lookups",expand=True)
    table.add_column("Domain")
    table.add_column("Lookups",justify="right")
    for domain, count in stats.top_dns_queries():
        table.add_row(domain,str(count))
    return table

def build_alerts_panel(alerts) -> Panel:
    lines = [f"[bold red]{format_time(a.timestamp)}[/] {a.message}" for a in alerts]
    return Panel("\n".join(lines), title="Alerts",border_style="red")

def build_dashboard(stats: TrafficStats, recent_lines, alerts=()) -> Group:
    
    tables = Table.grid(expand=True, padding=(0, 1))
    tables.add_column(ratio=1)
    tables.add_column(ratio=1)
    tables.add_row(build_services_table(stats), build_talkers_table(stats))

    recent = Panel("\n".join(recent_lines) or "Waiting for packets....",
                   title="Latest packets", border_style="dim")

    parts = [build_overview(stats)]
    if alerts:  
        parts.append(build_alerts_panel(alerts))
    parts += [tables, build_dns_table(stats), recent]
    return Group(*parts)

class Dashboard:
    def __init__(self, stats: TrafficStats, refresh_interval:float=0.5,
                 recent_count: int = 8) -> None:
        self.stats = stats
        self.refresh_interval = refresh_interval
        self.recent_lines = deque(maxlen=recent_count)
        self.alerts = deque(maxlen=5)
        self._last_refresh = 0.0
        self._live = Live(self.render(),auto_refresh=False)

    def render(self) -> Group:
        return build_dashboard(self.stats,self.recent_lines,self.alerts)

    def add(self,line:str) -> None:
        self.recent_lines.append(line)
        now = time.monotonic()
        if now - self._last_refresh >= self.refresh_interval:
            self._last_refresh = now
            self._live.update(self.render(),refresh=True)
            
    def add_alert(self,alert:Alert) -> None:
        self.alerts.append(alert)
        self._live.update(self.render(), refresh=True)
    def __enter__(self) -> "Dashboard":
        self._live.start()
        return self

    def __exit__(self, *exc) -> None:
        self._live.update(self.render(),refresh=True)
        self._live.stop
        