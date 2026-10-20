from datetime import datetime

from netwatch.models.connection import Connection, Endpoint, ProcessOutbound, Protocol, Snapshot, TrafficStats
from netwatch.models.process import ProcessIdentity
from netwatch.models.signals import Severity
from netwatch.monitoring.signals import MEBIBYTE, SignalDetector, evaluate, in_temp_dir, untrusted_alerts
from netwatch.storage.history import LEARNING_SECONDS, HistoryRecorder


def process(name="python3", *args, exe="/usr/bin/python3", deleted=False, cwd=None, pid=1):
    return ProcessIdentity(pid, name, exe, deleted, (name, *args), "user", (), cwd)


def summary(proc, sent=0, received=0):
    return ProcessOutbound(
        process_name=proc.label if proc else None,
        process=proc,
        connection_count=1,
        destinations=("6.6.6.6",),
        session_sent=sent,
        session_received=received,
    )


def codes(signals):
    return [signal.code for signal in signals]


def test_clean_process_has_no_signals():
    browser = process("firefox", exe="/snap/firefox/1/firefox")
    assert evaluate(summary(browser, sent=50 * MEBIBYTE, received=500 * MEBIBYTE), known=True) == ()


def test_deleted_executable_is_high():
    signals = evaluate(summary(process("sleep", exe="/home/u/sleep", deleted=True)), known=True)
    assert codes(signals) == ["exe_deleted"]
    assert signals[0].severity is Severity.HIGH


def test_temp_dir_for_executable_and_relative_script():
    assert codes(evaluate(summary(process("x", exe="/dev/shm/x")), None)) == ["temp_dir"]
    relative = process("python3", "sync.py", cwd="/tmp/.cache")
    assert relative.script_path == "/tmp/.cache/sync.py"
    assert codes(evaluate(summary(relative), None)) == ["temp_dir"]


def test_appimage_mount_is_not_flagged():
    assert not in_temp_dir("/tmp/.mount_CursorAbc123/cursor")
    assert in_temp_dir("/tmp/payload")


def test_interpreter_and_network_tool_upload_thresholds():
    assert evaluate(summary(process("python3", "/home/u/a.py"), sent=MEBIBYTE - 1, received=MEBIBYTE), None) == ()
    signals = evaluate(summary(process("python3", "/home/u/a.py"), sent=MEBIBYTE, received=MEBIBYTE), None)
    assert codes(signals) == ["script_upload"]
    curl = process("curl", "-T", "f", exe="/usr/bin/curl")
    assert codes(evaluate(summary(curl, sent=2 * MEBIBYTE, received=2 * MEBIBYTE), None)) == ["script_upload"]


def test_upload_heavy_ratio():
    app = process("rclone", exe="/usr/bin/rclone")
    assert codes(evaluate(summary(app, sent=6 * MEBIBYTE, received=MEBIBYTE), None)) == ["upload_heavy"]
    assert evaluate(summary(app, sent=6 * MEBIBYTE, received=2 * MEBIBYTE), None) == ()


def test_new_process_severity_depends_on_volume():
    app = process("tool", exe="/opt/tool")
    assert evaluate(summary(app), known=False)[0].severity is Severity.LOW
    assert evaluate(summary(app, sent=200 * 1024, received=10 * MEBIBYTE), known=False)[0].severity is Severity.MEDIUM
    assert evaluate(summary(app), known=None) == ()


def test_signals_sorted_by_severity():
    worst = process("python3", "/tmp/x.py", exe="/tmp/python3", deleted=True)
    signals = evaluate(summary(worst, sent=10 * MEBIBYTE), known=False)
    assert [s.severity for s in signals] == sorted((s.severity for s in signals), reverse=True)
    assert codes(signals)[:2] == ["exe_deleted", "temp_dir"]


def snapshot_with(*summaries):
    return Snapshot(datetime(2026, 1, 1), TrafficStats(None, None, 0, 0, ()), (), tuple(summaries), (), 0)


def test_detector_caches_known_lookup_and_reports_learning():
    calls = []

    def is_known(proc):
        calls.append(proc.pid)
        return False

    detector = SignalDetector(is_known, lambda: 123.0)
    app = process("tool", exe="/opt/tool")
    detector.apply(snapshot_with(summary(app)))
    result = detector.apply(snapshot_with(summary(app)))
    assert calls == [1]
    assert result.learning_until == 123.0
    assert codes(result.outbound_by_process[0].signals) == ["new_process"]


def test_untrusted_alerts_respects_trust():
    flagged = summary(process("x", exe="/tmp/x"))
    detector = SignalDetector()
    result = detector.apply(snapshot_with(flagged, summary(process("firefox", exe="/usr/bin/firefox"))))
    alerts = untrusted_alerts(result.outbound_by_process, set())
    assert [a.process_name for a in alerts] == ["x"]
    assert untrusted_alerts(result.outbound_by_process, {flagged.process.group_key}) == []


def test_recorder_learning_and_known_process(tmp_path):
    path = tmp_path / "history.db"
    base = datetime(2026, 1, 1).timestamp()
    first = HistoryRecorder(path, 30, clock=lambda: base)
    assert first.learning_until() == base + LEARNING_SECONDS
    assert first.seen_before_session("python3 a.py", "/usr/bin/python3") is None
    conn = Connection(
        Protocol.TCP, Endpoint("192.168.0.2", 1), Endpoint("6.6.6.6", 443), "ESTABLISHED", 1, "python3 a.py",
        process=process("python3", "a.py"),
    )
    first.record(Snapshot(datetime.fromtimestamp(base), TrafficStats(None, None, 0, 0, ()), (conn,), (), (), 0))
    first.close()

    later = HistoryRecorder(path, 30, clock=lambda: base + 2 * LEARNING_SECONDS)
    assert later.learning_until() is None
    assert later.seen_before_session("python3 a.py", "/usr/bin/python3") is True
    assert later.seen_before_session("python3 b.py", "/usr/bin/python3") is False
    later.close()


def test_plain_label_does_not_render_html(qapp):
    from netwatch.ui.plain import PlainLabel, plain_tooltip

    hidden = '<span style="font-size:1px">python3 /tmp/x.py</span>'
    assert PlainLabel(hidden).sizeHint().width() > PlainLabel("python3 /tmp/x.py").sizeHint().width()
    assert "<span" not in plain_tooltip(hidden)
    assert "&lt;span" in plain_tooltip(hidden)


def test_toggling_trust_keeps_alerts_table_consistent(qapp):
    from netwatch.ui.alerts_tab import AlertsTab

    tab = AlertsTab()
    tab.show()
    detected = SignalDetector().apply(snapshot_with(summary(process("x", exe="/tmp/x"))))
    tab.update_snapshot(detected)
    tab._table.selectRow(0)
    key = detected.outbound_by_process[0].process.group_key
    tab.set_trusted({key})
    tab.repaint()
    qapp.processEvents()
    assert tab._trust.text() == "Remover confiança"
    assert tab._model.data(tab._model.index(0, 5)) == "sim"
