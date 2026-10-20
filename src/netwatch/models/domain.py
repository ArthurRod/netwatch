from dataclasses import dataclass
from enum import StrEnum


class NameSource(StrEnum):
    DNS_OBSERVED = "dns_observed"
    DNS_AMBIGUOUS = "dns_ambiguous"
    REVERSE_CONFIRMED = "reverse_confirmed"
    REVERSE_UNCONFIRMED = "reverse_unconfirmed"


@dataclass(frozen=True, slots=True)
class RemoteName:
    name: str
    source: NameSource
    alternatives: tuple[str, ...] = ()

    @property
    def confirmed(self) -> bool:
        return self.source in (NameSource.DNS_OBSERVED, NameSource.REVERSE_CONFIRMED)
