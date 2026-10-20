from netwatch.models.connection import Connection, Endpoint, Protocol
from netwatch.models.domain import NameSource, RemoteName
from netwatch.models.process import ProcessIdentity

UNKNOWN = "—"
UNKNOWN_PROCESS = "sem permissão"
CLOSED_PROCESS = "encerrada"

_UNITS = ("B", "KB", "MB", "GB", "TB")

KNOWN_SERVICES = {
    (Protocol.UDP, 67): "DHCP",
    (Protocol.UDP, 547): "DHCPv6",
    (Protocol.UDP, 53): "DNS",
    (Protocol.TCP, 53): "DNS",
    (Protocol.TCP, 853): "DNS-over-TLS",
    (Protocol.UDP, 123): "NTP",
    (Protocol.UDP, 5353): "mDNS",
}


def format_bytes(value: float | None) -> str:
    if value is None:
        return UNKNOWN
    size = float(value)
    for unit in _UNITS:
        if abs(size) < 1024 or unit == _UNITS[-1]:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return UNKNOWN


def format_rate(value: float | None) -> str:
    return UNKNOWN if value is None else f"{format_bytes(value)}/s"


def format_endpoint(endpoint: Endpoint | None) -> str:
    if endpoint is None:
        return UNKNOWN
    host = f"[{endpoint.ip}]" if ":" in endpoint.ip else endpoint.ip
    return f"{host}:{endpoint.port}"


def process_label(name: str | None) -> str:
    return name or UNKNOWN_PROCESS


def service_hint(connection: Connection) -> str | None:
    if connection.remote is None:
        return None
    return KNOWN_SERVICES.get((connection.protocol, connection.remote.port))


def connection_process_label(connection: Connection) -> str:
    if connection.process_name is not None:
        return connection.process_name
    if connection.is_closed:
        return CLOSED_PROCESS
    service = service_hint(connection)
    return f"{UNKNOWN_PROCESS} · {service}" if service else UNKNOWN_PROCESS


def connection_label(connection: Connection) -> str:
    return f"{connection_process_label(connection)} → {format_endpoint(connection.remote)}"


def process_details(process: ProcessIdentity | None) -> str:
    if process is None:
        return "Processo não identificado: pertence a outro usuário e o PID não é visível sem privilégios."
    exe = process.exe or UNKNOWN
    if process.exe_deleted:
        exe = f"{exe}  ⚠ apagado do disco"
    lines = [
        f"Comando: {process.command}",
        f"Executável: {exe}",
        f"Usuário: {process.username or UNKNOWN} · PID {process.pid}",
        f"Iniciado por: {process.lineage or UNKNOWN}",
    ]
    return "\n".join(lines)


WIDGET_NAME_LIMIT = 30
UNCONFIRMED_NOTE = (
    "Nome reverso (PTR) não confirmado: o nome não resolve de volta para este IP. "
    "Quem controla o IP escolhe esse nome, então ele pode ser falso."
)
CONFIRMED_NOTE = (
    "Nome reverso (PTR) confirmado: o nome resolve de volta para este IP. "
    "Indica o dono da infraestrutura (ex.: provedor de nuvem ou CDN), não necessariamente o site acessado."
)


def format_remote_name(name: RemoteName | None) -> str:
    if name is None:
        return UNKNOWN
    return name.name if name.confirmed else f"{name.name}?"


DNS_OBSERVED_NOTE = "Nome observado numa consulta DNS real feita nesta máquina (helper eBPF)."


def remote_name_note(name: RemoteName | None) -> str | None:
    if name is None:
        return None
    if name.source is NameSource.DNS_OBSERVED:
        return DNS_OBSERVED_NOTE
    if name.source is NameSource.DNS_AMBIGUOUS:
        others = ", ".join(name.alternatives)
        return f"Este IP foi resposta DNS para mais de um nome (também: {others}); a associação é incerta."
    return CONFIRMED_NOTE if name.confirmed else UNCONFIRMED_NOTE


def short_destination(ip: str, name: RemoteName | None) -> str:
    if name is None or not name.confirmed:
        return ip
    text = name.name
    return text if len(text) <= WIDGET_NAME_LIMIT else "…" + text[-(WIDGET_NAME_LIMIT - 1):]


def destination_line(ip: str, name: RemoteName | None) -> str:
    return f"{ip}  {format_remote_name(name)}" if name else ip
