import json
import os
import socket
import time

import netwatch_helper as helper


def test_parse_connect_line():
    event = helper.parse_trace_line("C\t140001\t4242\t1000\t192.168.0.2\t50000\t6.6.6.6\t443\tcurl\n")
    assert event == {
        "type": "tcp_connect",
        "sock": 140001,
        "pid": 4242,
        "uid": 1000,
        "local": ["192.168.0.2", 50000],
        "remote": ["6.6.6.6", 443],
        "comm": "curl",
    }


def test_parse_close_line_with_unknown_owner():
    event = helper.parse_trace_line("X\t140001\t0\t0\t::1\t40000\t2001:db8::1\t443\t1234\t99\t\n")
    assert event["pid"] is None
    assert event["uid"] is None
    assert event["comm"] is None
    assert (event["bytes_sent"], event["bytes_received"]) == (1234, 99)


def test_malicious_comm_cannot_inject_fields():
    event = helper.parse_trace_line("C\t1\t42\t1000\t10.0.0.2\t1\t6.6.6.6\t443\tev\til\tX\t9\n")
    assert event["comm"] == "ev\til\tX\t9"
    assert event["remote"] == ["6.6.6.6", 443]


def test_garbage_lines_are_ignored():
    assert helper.parse_trace_line("C\tnot\ta\tnumber") is None
    assert helper.parse_trace_line("Attaching 3 probes...") is None


def test_parse_dns_reply():
    message = {
        "parameters": {
            "state": "success",
            "question": [{"class": 1, "type": 1, "name": "discord.com"}],
            "answer": [
                {"rr": {"key": {"class": 1, "type": 5, "name": "discord.com"}, "name": "x.cdn.net"}},
                {"rr": {"key": {"class": 1, "type": 1, "name": "x.cdn.net"}, "address": [162, 159, 135, 232]}},
                {"rr": {"key": {"class": 1, "type": 28, "name": "x.cdn.net."}, "address": [32, 1, 13, 184] + [0] * 11 + [1]}},
            ],
        },
        "continues": True,
    }
    assert helper.parse_dns_reply(message) == {
        "type": "dns",
        "questions": ["discord.com"],
        "answers": {"x.cdn.net": ["162.159.135.232", "2001:db8::1"]},
    }
    assert helper.parse_dns_reply({"parameters": {"ready": True}}) is None


def test_process_inspector_reads_own_process():
    identity = helper.ProcessInspector().identity(os.getpid())
    assert identity["pid"] == os.getpid()
    assert identity["exe"] and not identity["exe_deleted"]
    assert identity["uid"] == os.getuid()
    assert identity["ancestors"][0][0] == os.getppid()
    assert helper.ProcessInspector().identity(0) is None
    assert helper.ProcessInspector().identity(2**22 + 12345) is None


def test_enricher_keeps_connect_identity_for_close():
    class FakeInspector:
        calls = []

        def identity(self, pid):
            self.calls.append(pid)
            return {"pid": pid, "name": "curl"} if pid == 42 else None

    enricher = helper.TcpEnricher(FakeInspector())
    enricher.enrich({"type": "tcp_connect", "sock": 7, "pid": 42})
    closed = enricher.enrich({"type": "tcp_close", "sock": 7, "pid": None})
    assert closed["process"] == {"pid": 42, "name": "curl"}


def read_line(connection):
    data = b""
    while not data.endswith(b"\n"):
        chunk = connection.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def test_server_streams_to_allowed_uid_and_rejects_others(tmp_path):
    broadcaster = helper.Broadcaster()
    path = tmp_path / "events.sock"
    server = helper.EventServer(path, {os.getuid()}, broadcaster, {"type": "hello", "version": 1})
    server.start()
    assert oct(path.stat().st_mode & 0o777) == "0o666"
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(str(path))
    client.settimeout(2)
    assert json.loads(read_line(client))["type"] == "hello"
    for _ in range(50):
        broadcaster.publish({"type": "status", "tcp": "running"})
        time.sleep(0.02)
        if broadcaster._clients:
            break
    assert json.loads(read_line(client))["type"] == "status"
    client.close()
    server.stop()

    denied = helper.EventServer(path, {os.getuid() + 1}, helper.Broadcaster(), {"type": "hello"})
    denied.start()
    other = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    other.connect(str(path))
    other.settimeout(2)
    assert other.recv(100) == b""
    denied.stop()


def test_slow_client_drops_instead_of_blocking():
    broadcaster = helper.Broadcaster()
    client = broadcaster.subscribe()
    for _ in range(helper.CLIENT_QUEUE_SIZE + 5):
        broadcaster.publish({"type": "x"})
    assert client.qsize() == helper.CLIENT_QUEUE_SIZE
    assert broadcaster.dropped == 5
