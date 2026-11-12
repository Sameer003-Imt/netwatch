from netwatch.alertlog import AlertLog, read_alert_log
from netwatch.detectors import Alert

def test_alerts_are_saved_and_read_back(tmp_path):
    path = str(tmp_path/"alerts.jsonl")
    alert = Alert(1_700_000_000.0, "PORT_SCAN","192.168.1.66","192.168.1.10",
                  "Possible port scan")
    with AlertLog(path) as log:
        log.write(alert)
        log.write(alert)

    records = read_alert_log(path)
    assert len(records) == 2
    assert records[0]["kind"] == "PORT_SCAN"
    assert records[0]["source_ip"] == "192.168.1.66"
    assert records[0]["time"] == "2023-11-14T22:13:20+00:00"

def test_new_alerts_are_added_to_the_end(tmp_path):
    path = str(tmp_path / "alerts.jsonl")
    alert = Alert(0.0,"TRAFFIC_SPIKE","*","*","Traffic spike")
    with AlertLog(path) as log:
        log.write(alert)
    with AlertLog(path) as log:
        log.write(alert)
    assert len(read_alert_log(path)) == 2
    