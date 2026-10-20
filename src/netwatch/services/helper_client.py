import json
import logging
import socket
import threading
import time
from collections import deque
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_SOCKET = Path("/run/netwatch-helper/events.sock")
RECONNECT_SECONDS = 5
MAX_PENDING_EVENTS = 50_000
MAX_LINE_BYTES = 1_000_000


class HelperClient:
    def __init__(self, path: Path = DEFAULT_SOCKET) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._events: deque[dict] = deque(maxlen=MAX_PENDING_EVENTS)
        self._status: dict[str, str] = {}
        self._connected = False
        self._stop = threading.Event()
        self._socket: socket.socket | None = None
        self._thread = threading.Thread(target=self._run, name="netwatch-helper-client", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        connection = self._socket
        if connection is not None:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    @property
    def connected(self) -> bool:
        return self._connected

    def status(self) -> dict[str, str]:
        with self._lock:
            return dict(self._status)

    def drain(self) -> list[dict]:
        with self._lock:
            events = list(self._events)
            self._events.clear()
        return events

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._read_stream()
            except OSError:
                pass
            self._connected = False
            self._stop.wait(RECONNECT_SECONDS)

    def _read_stream(self) -> None:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket = connection
        try:
            connection.connect(str(self._path))
            buffer = b""
            while not self._stop.is_set():
                chunk = connection.recv(65536)
                if not chunk:
                    return
                buffer += chunk
                if len(buffer) > MAX_LINE_BYTES and b"\n" not in buffer:
                    raise OSError("helper sent an oversized line")
                *lines, buffer = buffer.split(b"\n")
                for line in lines:
                    self._handle(line)
        finally:
            self._socket = None
            connection.close()

    def _handle(self, line: bytes) -> None:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return
        if not isinstance(event, dict):
            return
        kind = event.get("type")
        if kind == "hello":
            self._connected = True
            logger.info("Connected to NetWatch helper (protocol %s)", event.get("version"))
        elif kind == "status":
            with self._lock:
                self._status = {key: str(value) for key, value in event.items() if key in ("tcp", "dns")}
        else:
            with self._lock:
                self._events.append(event)
