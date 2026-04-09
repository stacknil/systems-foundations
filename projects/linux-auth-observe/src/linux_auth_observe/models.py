from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping
import json


@dataclass(slots=True)
class NormalizedEvent:
    ts: str
    host: str
    collector: str
    parser: str
    event_family: str
    event_type: str
    outcome: str
    user: str | None
    src_ip: str | None
    src_port: int | None
    service: str | None
    unit: str | None
    pid: int | None
    program: str | None
    message: str
    raw: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "NormalizedEvent":
        return cls(
            ts=str(payload["ts"]),
            host=str(payload["host"]),
            collector=str(payload["collector"]),
            parser=str(payload["parser"]),
            event_family=str(payload["event_family"]),
            event_type=str(payload["event_type"]),
            outcome=str(payload["outcome"]),
            user=_coerce_optional_text(payload.get("user")),
            src_ip=_coerce_optional_text(payload.get("src_ip")),
            src_port=_coerce_optional_int(payload.get("src_port")),
            service=_coerce_optional_text(payload.get("service")),
            unit=_coerce_optional_text(payload.get("unit")),
            pid=_coerce_optional_int(payload.get("pid")),
            program=_coerce_optional_text(payload.get("program")),
            message=str(payload["message"]),
            raw=str(payload["raw"]),
        )


def _coerce_optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _coerce_optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    return int(value)
