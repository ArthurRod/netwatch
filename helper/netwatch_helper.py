import argparse
import json
import logging
import os
import queue
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

VERSION = 1
SOCKET_PATH = Path("/run/netwatch-helper/events.sock")
CONFIG_PATH = Path("/etc/netwatch-helper.conf")
PROGRAM_PATH = Path(__file__).with_name("netwatch.bt")
RESOLVED_MONITOR = "/run/systemd/resolve/io.systemd.Resolve.Monitor"
BPFTRACE = "bpftrace"
MAX_MAP_KEYS = "65536"
CLIENT_QUEUE_SIZE = 20_000
ANCESTOR_LIMIT = 4
RESTART_DELAYS = (1, 2, 5, 10, 30)
IDENTITY_CACHE_LIMIT = 4096
SOCKET_CACHE_LIMIT = 65_536
DNS_RECORD_TYPES = {1: 4, 28: 6}

logger = logging.getLogger("netwatch-helper")


def parse_trace_line(data: str) -> dict | None:
    line = data.rstrip("\n")
    kind, _, rest = line.partition("\t")
    try:
        if kind == "C":
            sock, pid, uid, saddr, sport, daddr, dport, comm = rest.split("\t", 7)
            return {
                "type": "tcp_connect",
                "sock": int(sock),
                "pid": int(pid),
                "uid": int(uid),
                "local": [saddr, int(sport)],
                "remote": [daddr, int(dport)],
                "comm": comm,
            }
        if kind == "X":
            sock, pid, uid, saddr, sport, daddr, dport, sent, received, comm = rest.split("\t", 9)
            return {
                "type": "tcp_close",
                "sock": int(sock),
                "pid": int(pid) or None,
                "uid": int(uid) if int(pid) else None,
                "local": [saddr, int(sport)],
                "remote": [daddr, int(dport)],
                "bytes_sent": int(sent),
                "bytes_received": int(received),
                "comm": comm or None,
            }
    except ValueError:
        return None
    return None


def _read(path: str) -> str | None:
    try:
        with open(path, "rb") as file:
            return file.read().decode("utf-8", "replace")
    except OSError:
        return None


def _readlink(path: str) -> str | None:
    try:
        return os.readlink(path)
    except OSError:
        return None


def _stat_fields(pid: int) -> tuple[str, int, int] | None:
    stat = _read(f"/proc/{pid}/stat")
    if stat is None or ")" not in stat:
        return None
    name = stat[stat.index("(") + 1 : stat.rindex(")")]
    fields = stat[stat.rindex(")") + 2 :].split()
    return name, int(fields[1]), int(fields[19])


class ProcessInspector:
    def __init__(self, proc: str = "/proc") -> None:
        self._proc = proc
        self._cache: dict[tuple[int, int], dict] = {}

    def identity(self, pid: int | None) -> dict | None:
        if not pid:
            return None
        stat = _stat_fields(pid)
        if stat is None:
            return None
        name, _, start_time = stat
        key = (pid, start_time)
        if key not in self._cache:
            if len(self._cache) >= IDENTITY_CACHE_LIMIT:
                self._cache.clear()
            self._cache[key] = self._inspect(pid, name)
        return self._cache[key]

    def _inspect(self, pid: int, name: str) -> dict:
        exe = _readlink(f"/proc/{pid}/exe")
        deleted = bool(exe and exe.endswith(" (deleted)"))
        if deleted:
            exe = exe[: -len(" (deleted)")]
        cmdline = _read(f"/proc/{pid}/cmdline") or ""
        status = _read(f"/proc/{pid}/status") or ""
        uid = next((int(line.split()[1]) for line in status.splitlines() if line.startswith("Uid:")), None)
        return {
            "pid": pid,
            "name": (_read(f"/proc/{pid}/comm") or name).strip(),
            "exe": exe,
            "exe_deleted": deleted,
            "cmdline": [part for part in cmdline.split("\0") if part],
            "uid": uid,
            "cwd": _readlink(f"/proc/{pid}/cwd"),
            "ancestors": self._ancestors(pid),
        }

    @staticmethod
    def _ancestors(pid: int) -> list[list]:
        ancestors = []
        current = pid
        for _ in range(ANCESTOR_LIMIT):
            stat = _stat_fields(current)
            if stat is None or stat[1] <= 0:
                break
            parent = _stat_fields(stat[1])
            if parent is None:
                break
            ancestors.append([stat[1], parent[0]])
            current = stat[1]
        return ancestors


class Broadcaster:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._clients: list[queue.Queue] = []
        self.dropped = 0

    def subscribe(self) -> queue.Queue:
        client: queue.Queue = queue.Queue(maxsize=CLIENT_QUEUE_SIZE)
        with self._lock:
            self._clients.append(client)
        return client

    def unsubscribe(self, client: queue.Queue) -> None:
        with self._lock:
            if client in self._clients:
                self._clients.remove(client)

    def publish(self, event: dict) -> None:
        payload = (json.dumps(event, separators=(",", ":")) + "\n").encode()
        with self._lock:
            clients = list(self._clients)
        for client in clients:
            try:
                client.put_nowait(payload)
            except queue.Full:
                self.dropped += 1


class TcpEnricher:
    def __init__(self, inspector: ProcessInspector) -> None:
        self._inspector = inspector
        self._sockets: dict[int, dict | None] = {}

    def enrich(self, event: dict) -> dict:
        event["ts"] = time.time()
        if event["type"] == "tcp_connect":
            process = self._inspector.identity(event["pid"])
            if len(self._sockets) >= SOCKET_CACHE_LIMIT:
                self._sockets.clear()
            self._sockets[event["sock"]] = process
        else:
            process = self._sockets.pop(event["sock"], None) or self._inspector.identity(event["pid"])
        event["process"] = process
        return event


def peer_uid(connection: socket.socket) -> int:
    credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", credentials)[1]


class EventServer:
    def __init__(self, path: Path, allowed_uids: set[int], broadcaster: Broadcaster, hello: dict) -> None:
        self._path = path
        self._allowed = allowed_uids
        self._broadcaster = broadcaster
        self._hello = hello
        self._server: socket.socket | None = None

    def start(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.unlink(missing_ok=True)
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(str(self._path))
        os.chmod(self._path, 0o666)
        self._server.listen(8)
        threading.Thread(target=self._accept_loop, name="accept", daemon=True).start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.close()
        self._path.unlink(missing_ok=True)

    def _accept_loop(self) -> None:
        while True:
            try:
                connection, _ = self._server.accept()
            except OSError:
                return
            uid = peer_uid(connection)
            if uid not in self._allowed:
                logger.warning("Rejected client with uid %s", uid)
                connection.close()
                continue
            threading.Thread(target=self._serve, args=(connection,), name=f"client-{uid}", daemon=True).start()

    def _serve(self, connection: socket.socket) -> None:
        client = self._broadcaster.subscribe()
        connection.shutdown(socket.SHUT_RD)
        try:
            connection.sendall((json.dumps(self._hello) + "\n").encode())
            while True:
                connection.sendall(client.get())
        except OSError:
            pass
        finally:
            self._broadcaster.unsubscribe(client)
            connection.close()


def _dns_addresses(rr: dict) -> tuple[str, str] | None:
    key = rr.get("key") or {}
    family = DNS_RECORD_TYPES.get(key.get("type"))
    raw = rr.get("address")
    name = key.get("name")
    if family is None or not isinstance(raw, list) or not name:
        return None
    try:
        packed = bytes(raw)
        address = socket.inet_ntop(socket.AF_INET if family == 4 else socket.AF_INET6, packed)
    except (ValueError, OSError):
        return None
    return name.rstrip("."), address


def parse_dns_reply(message: dict) -> dict | None:
    parameters = message.get("parameters") or {}
    answers = parameters.get("answer") or []
    questions = [q.get("name", "").rstrip(".") for q in parameters.get("question") or [] if q.get("name")]
    addresses: dict[str, list[str]] = {}
    for answer in answers:
        parsed = _dns_addresses(answer.get("rr") or {})
        if parsed is not None:
            addresses.setdefault(parsed[0], []).append(parsed[1])
    if not addresses:
        return None
    return {"type": "dns", "questions": questions, "answers": addresses}


class DnsMonitor:
    def __init__(self, broadcaster: Broadcaster, status: "HelperStatus") -> None:
        self._broadcaster = broadcaster
        self._status = status
        self.last_raw: str | None = None

    def run(self) -> None:
        delays = iter(RESTART_DELAYS)
        while True:
            try:
                self._subscribe()
            except OSError as error:
                self._status.set("dns", f"failed: {error}")
            time.sleep(next(delays, RESTART_DELAYS[-1]))

    def _subscribe(self) -> None:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.connect(RESOLVED_MONITOR)
        request = {"method": "io.systemd.Resolve.Monitor.SubscribeQueryResults", "more": True}
        connection.sendall(json.dumps(request).encode() + b"\0")
        buffer = b""
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                raise OSError("resolved closed the connection")
            buffer += chunk
            while b"\0" in buffer:
                raw, buffer = buffer.split(b"\0", 1)
                self.last_raw = raw[:800].decode("utf-8", "replace")
                message = json.loads(raw)
                if "error" in message:
                    raise OSError(message["error"])
                self._status.set("dns", "running")
                event = parse_dns_reply(message)
                if event is not None:
                    event["ts"] = time.time()
                    self._broadcaster.publish(event)


class HelperStatus:
    def __init__(self, broadcaster: Broadcaster) -> None:
        self._broadcaster = broadcaster
        self._lock = threading.Lock()
        self.values = {"tcp": "starting", "dns": "starting"}

    def set(self, component: str, value: str) -> None:
        with self._lock:
            if self.values.get(component) == value:
                return
            self.values[component] = value
            snapshot = dict(self.values)
        logger.info("%s: %s", component, value)
        self._broadcaster.publish({"type": "status", "ts": time.time(), **snapshot})


class TcpTracer:
    def __init__(self, broadcaster: Broadcaster, status: HelperStatus, enricher: TcpEnricher) -> None:
        self._broadcaster = broadcaster
        self._status = status
        self._enricher = enricher

    def run(self) -> None:
        delays = iter(RESTART_DELAYS)
        while True:
            self._run_once()
            time.sleep(next(delays, RESTART_DELAYS[-1]))

    def _run_once(self) -> None:
        env = dict(os.environ, BPFTRACE_MAX_MAP_KEYS=MAX_MAP_KEYS)
        try:
            process = subprocess.Popen(
                [BPFTRACE, "-f", "json", str(PROGRAM_PATH)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
        except OSError as error:
            self._status.set("tcp", f"failed: {error}")
            return
        threading.Thread(target=self._log_stderr, args=(process,), daemon=True).start()
        for line in process.stdout:
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            kind = message.get("type")
            if kind == "attached_probes":
                self._status.set("tcp", "running")
            elif kind == "printf":
                event = parse_trace_line(message.get("data", ""))
                if event is not None:
                    self._broadcaster.publish(self._enricher.enrich(event))
            elif kind == "lost_events":
                logger.warning("bpftrace lost events: %s", message.get("data"))
        code = process.wait()
        self._status.set("tcp", f"failed: bpftrace exited with {code}")

    @staticmethod
    def _log_stderr(process: subprocess.Popen) -> None:
        for line in process.stderr:
            logger.warning("bpftrace: %s", line.rstrip())


def load_allowed_uids(path: Path = CONFIG_PATH) -> set[int]:
    try:
        config = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"cannot read {path}: {error}")
    return {int(uid) for uid in config.get("allowed_uids", [])}


def start_components() -> tuple[Broadcaster, HelperStatus, DnsMonitor]:
    broadcaster = Broadcaster()
    status = HelperStatus(broadcaster)
    tracer = TcpTracer(broadcaster, status, TcpEnricher(ProcessInspector()))
    dns = DnsMonitor(broadcaster, status)
    threading.Thread(target=tracer.run, name="tcp", daemon=True).start()
    threading.Thread(target=dns.run, name="dns", daemon=True).start()
    return broadcaster, status, dns


def serve() -> None:
    allowed = load_allowed_uids()
    broadcaster, status, _ = start_components()
    server = EventServer(SOCKET_PATH, allowed, broadcaster, {"type": "hello", "version": VERSION})
    server.start()
    logger.info("Serving events on %s for uids %s", SOCKET_PATH, sorted(allowed))
    try:
        threading.Event().wait()
    finally:
        server.stop()


def self_test(attach_timeout: float = 30.0, event_timeout: float = 10.0) -> int:
    broadcaster, status, dns = start_components()
    events = broadcaster.subscribe()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    attach_deadline = time.time() + attach_timeout
    while status.values["tcp"] == "starting" and time.time() < attach_deadline:
        time.sleep(0.2)
    deadline = time.time() + event_timeout
    seen = {"tcp_connect": False, "tcp_close": False, "dns": False}
    client = socket.create_connection(("127.0.0.1", port))
    accepted, _ = listener.accept()
    client.sendall(b"netwatch-self-test")
    accepted.recv(64)
    client.close()
    accepted.close()
    try:
        socket.getaddrinfo(f"netwatch-self-test-{int(time.time())}.example.com", 443)
    except OSError:
        pass
    try:
        socket.getaddrinfo("example.com", 443)
    except OSError:
        pass
    sample_dns = None
    while time.time() < deadline and not all(seen.values()):
        try:
            event = json.loads(events.get(timeout=0.5))
        except queue.Empty:
            continue
        if event["type"] in ("tcp_connect", "tcp_close") and event["remote"][1] == port:
            seen[event["type"]] = True
            if event["type"] == "tcp_close":
                print(f"tcp_close: {event['bytes_sent']} bytes enviados, processo={(event['process'] or {}).get('exe')}")
        elif event["type"] == "dns":
            seen["dns"] = True
            sample_dns = sample_dns or event
    print(f"status: {status.values}")
    for name, ok in seen.items():
        print(f"{name}: {'OK' if ok else 'NÃO RECEBIDO'}")
    if sample_dns:
        print(f"exemplo dns: {json.dumps(sample_dns)[:300]}")
    elif dns.last_raw:
        print(f"mensagem crua do resolved: {dns.last_raw}")
    print(f"eventos descartados: {broadcaster.dropped}")
    return 0 if seen["tcp_connect"] and seen["tcp_close"] else 1


def main() -> None:
    parser = argparse.ArgumentParser(prog="netwatch-helper")
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stderr)
    if os.geteuid() != 0:
        raise SystemExit("netwatch-helper must run as root")
    if arguments.self_test:
        raise SystemExit(self_test())
    serve()


if __name__ == "__main__":
    main()
