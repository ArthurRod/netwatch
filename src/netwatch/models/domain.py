from dataclasses import dataclass
from enum import StrEnum


class NameSource(StrEnum):
    REVERSE_CONFIRMED = "reverse_confirmed"
    REVERSE_UNCONFIRMED = "reverse_unconfirmed"


@dataclass(frozen=True, slots=True)
class RemoteName:
    name: str
    source: NameSource

    @property
    def confirmed(self) -> bool:
        return self.source is NameSource.REVERSE_CONFIRMED
