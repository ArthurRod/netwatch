import logging
import socket
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable
from concurrent.futures import Future, ThreadPoolExecutor

from netwatch.models.connection import normalize_ip
from netwatch.models.domain import NameSource, RemoteName

logger = logging.getLogger(__name__)

POSITIVE_TTL_SECONDS = 3600
NEGATIVE_TTL_SECONDS = 600
MAX_CACHE_ENTRIES = 4096
MAX_REQUESTS_PER_CALL = 16
WORKERS = 4


def reverse_lookup(ip: str) -> RemoteName | None:
    try:
        name = socket.gethostbyaddr(ip)[0].rstrip(".")
    except (OSError, UnicodeError):
        return None
    try:
        forward = {normalize_ip(info[4][0]) for info in socket.getaddrinfo(name, None)}
    except (OSError, UnicodeError):
        forward = set()
    source = NameSource.REVERSE_CONFIRMED if normalize_ip(ip) in forward else NameSource.REVERSE_UNCONFIRMED
    return RemoteName(name, source)


class DomainResolver:
    def __init__(
        self,
        lookup: Callable[[str], RemoteName | None] = reverse_lookup,
        clock: Callable[[], float] = time.monotonic,
        workers: int = WORKERS,
    ) -> None:
        self._lookup = lookup
        self._clock = clock
        self._executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="netwatch-dns")
        self._lock = threading.Lock()
        self._cache: OrderedDict[str, tuple[RemoteName | None, float]] = OrderedDict()
        self._pending: set[str] = set()
        self._closed = False

    def name_for(self, ip: str) -> RemoteName | None:
        with self._lock:
            entry = self._cache.get(ip)
        return entry[0] if entry else None

    def request(self, ips: Iterable[str]) -> None:
        now = self._clock()
        selected = []
        with self._lock:
            if self._closed:
                return
            for ip in dict.fromkeys(ips):
                if len(selected) >= MAX_REQUESTS_PER_CALL:
                    break
                entry = self._cache.get(ip)
                if ip in self._pending or (entry is not None and entry[1] > now):
                    continue
                self._pending.add(ip)
                selected.append(ip)
        for ip in selected:
            future = self._executor.submit(self._lookup, ip)
            future.add_done_callback(lambda done, ip=ip: self._store(ip, done))

    def close(self) -> None:
        with self._lock:
            self._closed = True
        self._executor.shutdown(wait=False, cancel_futures=True)

    def _store(self, ip: str, future: Future) -> None:
        if future.cancelled():
            result = None
        else:
            try:
                result = future.result()
            except Exception:
                logger.exception("Reverse lookup failed for %s", ip)
                result = None
        ttl = POSITIVE_TTL_SECONDS if result is not None else NEGATIVE_TTL_SECONDS
        with self._lock:
            self._pending.discard(ip)
            self._cache[ip] = (result, self._clock() + ttl)
            self._cache.move_to_end(ip)
            while len(self._cache) > MAX_CACHE_ENTRIES:
                self._cache.popitem(last=False)
