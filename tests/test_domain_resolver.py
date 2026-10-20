import socket
import threading
from datetime import datetime

from netwatch.models.connection import Connection, Endpoint, Protocol, Snapshot, TrafficStats
from netwatch.models.domain import NameSource, RemoteName
from netwatch.models.history import HistoryQuery
from netwatch.services import domain_resolver
from netwatch.services.domain_resolver import (
    MAX_REQUESTS_PER_CALL,
    NEGATIVE_TTL_SECONDS,
    DomainResolver,
    reverse_lookup,
)
from netwatch.storage.history import HistoryReader, HistoryRecorder

CONFIRMED = RemoteName("edge.example.net", NameSource.REVERSE_CONFIRMED)


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def wait_for(resolver, ip):
    for _ in range(200):
        if ip not in resolver._pending:
            return
        threading.Event().wait(0.01)
    raise AssertionError("lookup did not finish")


def test_caches_results_and_deduplicates_requests():
    calls = []

    def lookup(ip):
        calls.append(ip)
        return CONFIRMED

    resolver = DomainResolver(lookup, Clock(), workers=1)
    resolver.request(["1.1.1.1", "1.1.1.1"])
    wait_for(resolver, "1.1.1.1")
    resolver.request(["1.1.1.1"])
    assert resolver.name_for("1.1.1.1") == CONFIRMED
    assert calls == ["1.1.1.1"]
    resolver.close()


def test_negative_results_expire_and_are_retried():
    clock = Clock()
    calls = []

    def lookup(ip):
        calls.append(ip)
        return None

    resolver = DomainResolver(lookup, clock, workers=1)
    resolver.request(["9.9.9.9"])
    wait_for(resolver, "9.9.9.9")
    resolver.request(["9.9.9.9"])
    assert len(calls) == 1
    clock.now += NEGATIVE_TTL_SECONDS + 1
    resolver.request(["9.9.9.9"])
    wait_for(resolver, "9.9.9.9")
    assert len(calls) == 2
    assert resolver.name_for("9.9.9.9") is None
    resolver.close()


def test_limits_requests_per_call():
    release = threading.Event()

    def lookup(ip):
        release.wait(1)
        return None

    resolver = DomainResolver(lookup, Clock(), workers=2)
    resolver.request([f"10.0.0.{i}" for i in range(MAX_REQUESTS_PER_CALL + 10)])
    assert len(resolver._pending) == MAX_REQUESTS_PER_CALL
    release.set()
    resolver.close()


def test_failing_lookup_is_cached_as_unknown():
    def lookup(ip):
        raise RuntimeError("boom")

    resolver = DomainResolver(lookup, Clock(), workers=1)
    resolver.request(["8.8.8.8"])
    wait_for(resolver, "8.8.8.8")
    assert resolver.name_for("8.8.8.8") is None
    resolver.close()


def test_reverse_lookup_confirms_with_forward_resolution(monkeypatch):
    monkeypatch.setattr(socket, "gethostbyaddr", lambda ip: ("host.example.net.", [], [ip]))
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda name, port: [(0, 0, 0, "", ("6.6.6.6", 0)), (0, 0, 0, "", ("7.7.7.7", 0))]
    )
    assert reverse_lookup("6.6.6.6") == RemoteName("host.example.net", NameSource.REVERSE_CONFIRMED)
    assert reverse_lookup("8.8.8.8") == RemoteName("host.example.net", NameSource.REVERSE_UNCONFIRMED)


def test_spoofed_ptr_that_does_not_resolve_is_unconfirmed(monkeypatch):
    def no_forward(name, port):
        raise socket.gaierror("no such name")

    monkeypatch.setattr(socket, "gethostbyaddr", lambda ip: ("update.microsoft.com", [], [ip]))
    monkeypatch.setattr(socket, "getaddrinfo", no_forward)
    assert reverse_lookup("6.6.6.6").source is NameSource.REVERSE_UNCONFIRMED


def test_no_ptr_returns_none(monkeypatch):
    def missing(ip):
        raise socket.herror("not found")

    monkeypatch.setattr(socket, "gethostbyaddr", missing)
    assert reverse_lookup("6.6.6.6") is None
    assert domain_resolver.POSITIVE_TTL_SECONDS > NEGATIVE_TTL_SECONDS


def test_name_arriving_later_updates_history_and_is_searchable(tmp_path):
    path = tmp_path / "history.db"
    recorder = HistoryRecorder(path, 30, clock=lambda: 0.0)
    base = Connection(Protocol.TCP, Endpoint("192.168.0.2", 1), Endpoint("6.6.6.6", 443), "ESTABLISHED", 1, "app")

    def snapshot(offset, connection):
        return Snapshot(datetime.fromtimestamp(1_000_000 + offset), TrafficStats(None, None, 0, 0, ()), (connection,), (), (), 0)

    recorder.record(snapshot(0, base))
    named = Connection(**{**{f: getattr(base, f) for f in base.__slots__}, "remote_name": CONFIRMED})
    recorder.record(snapshot(1, named))
    recorder.close()
    entries = HistoryReader(path).connections(HistoryQuery(search="edge.example"))
    assert [(e.remote_name, e.remote_name_confirmed) for e in entries] == [("edge.example.net", True)]
