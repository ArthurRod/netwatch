import os
import subprocess
import sys
import time

from netwatch.models.connection import Connection, Endpoint, Protocol
from netwatch.models.process import ProcessIdentity, redact_arguments
from netwatch.monitoring.collector import summarize_outbound
from netwatch.monitoring.connections import lookup_process
from netwatch.monitoring.process_traffic import ProcessTrafficTracker


def make(name, *args, exe=None, pid=1):
    return ProcessIdentity(pid, name, exe or f"/usr/bin/{name}", False, (name, *args), "user", ())


def test_script_and_label_for_interpreters():
    assert make("python3", "-u", "/tmp/.x/sync.py", "--fast").script == "/tmp/.x/sync.py"
    assert make("python3", "-u", "/tmp/.x/sync.py").label == "python3 sync.py"
    assert make("python3", "-m", "http.server").label == "python3 -m http.server"
    assert make("bash", "-c", "curl -d @/etc/passwd x").label == "bash -c"
    assert make("node", "server.js").label == "node server.js"
    assert make("python3.12").label == "python3.12"


def test_non_interpreter_keeps_plain_name():
    process = make("firefox", "-P", "default", "/tmp/file.html")
    assert process.script is None
    assert process.label == "firefox"


def test_different_scripts_of_same_interpreter_are_different_groups():
    assert make("python3", "a.py").group_key != make("python3", "b.py").group_key
    assert make("python3", "a.py", pid=1).group_key == make("python3", "a.py", pid=2).group_key


def test_redaction():
    assert redact_arguments(("curl", "-H", "Authorization: Bearer abc.def", "https://u:pw@host/x")) == (
        "curl",
        "-H",
        "Authorization: Bearer ***",
        "https://u:***@host/x",
    )
    assert redact_arguments(("app", "--password", "hunter2", "--api-key=XYZ", "TOKEN=abc", "--port", "80")) == (
        "app",
        "--password",
        "***",
        "--api-key=***",
        "TOKEN=***",
        "--port",
        "80",
    )


def tcp(process, port, sent):
    return Connection(
        Protocol.TCP,
        Endpoint("192.168.0.2", port),
        Endpoint("9.9.9.9", 443),
        "ESTABLISHED",
        process.pid,
        process.label,
        bytes_sent=sent,
        process=process,
    )


def test_traffic_split_between_two_python_scripts():
    good, bad = make("python3", "/home/u/app.py"), make("python3", "/tmp/.x/sync.py", pid=2)
    clock = iter([0.0, 1.0])
    tracker = ProcessTrafficTracker(lambda: next(clock))
    tracker.update([tcp(good, 1, 0), tcp(bad, 2, 0)])
    connections = [tcp(good, 1, 100), tcp(bad, 2, 9000)]
    summary = summarize_outbound(connections, tracker.update(connections))
    assert [(s.process_name, s.session_sent) for s in summary] == [("python3 sync.py", 9000), ("python3 app.py", 100)]
    assert summary[0].process.cmdline == ("python3", "/tmp/.x/sync.py")


def test_lookup_real_process_with_deleted_executable(tmp_path):
    copy = tmp_path / "sleep"
    copy.write_bytes(open("/usr/bin/sleep", "rb").read())
    copy.chmod(0o755)
    child = subprocess.Popen([str(copy), "5"])
    try:
        time.sleep(0.2)
        os.unlink(copy)
        process = lookup_process(child.pid)
        assert process.exe_deleted
        assert process.name == "sleep"
        assert process.ancestors[0][0] == os.getpid()
    finally:
        child.kill()
        child.wait()


def test_lookup_current_process():
    process = lookup_process(os.getpid())
    assert process.exe == os.path.realpath(sys.executable)
    assert not process.exe_deleted


def test_search_matches_command_path_and_handles_unknown_process(qapp):
    from netwatch.ui.connection_table import ConnectionFilterProxy, ConnectionTableModel

    unknown = Connection(Protocol.UDP, Endpoint("192.168.0.2", 68), Endpoint("192.168.0.1", 67), None, None, None)
    model = ConnectionTableModel()
    model.set_connections([tcp(make("python3", "/tmp/.x/sync.py"), 1, 0), unknown])
    proxy = ConnectionFilterProxy()
    proxy.setSourceModel(model)
    proxy.set_search("/tmp/.x")
    assert proxy.rowCount() == 1
    proxy.set_search("192.168.0.1")
    assert proxy.rowCount() == 1
