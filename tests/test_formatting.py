from netwatch.models.connection import Connection, Endpoint, Protocol
from netwatch.ui.formatting import connection_process_label, service_hint


def make(protocol, port, name=None, status=None):
    return Connection(protocol, Endpoint("192.168.0.2", 68), Endpoint("192.168.0.1", port), status, None, name)


def test_unattributed_dhcp_gets_service_hint():
    assert connection_process_label(make(Protocol.UDP, 67)) == "sem permissão · DHCP"


def test_hint_depends_on_protocol():
    assert service_hint(make(Protocol.TCP, 67)) is None
    assert connection_process_label(make(Protocol.TCP, 67)) == "sem permissão"


def test_known_process_name_is_kept():
    assert connection_process_label(make(Protocol.UDP, 53, name="systemd-resolved")) == "systemd-resolved"


def test_closed_connection_label_wins_over_hint():
    assert connection_process_label(make(Protocol.TCP, 53, status="TIME_WAIT")) == "encerrada"
