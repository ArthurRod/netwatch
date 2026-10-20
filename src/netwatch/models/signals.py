from dataclasses import dataclass
from enum import IntEnum


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3


SEVERITY_LABELS = {Severity.LOW: "baixa", Severity.MEDIUM: "média", Severity.HIGH: "alta"}


@dataclass(frozen=True, slots=True)
class Signal:
    code: str
    severity: Severity
    message: str
