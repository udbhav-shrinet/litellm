"""Who did what on which dataplane through the control plane. Bounded in memory plus a structured log line."""

import json
from collections import deque
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Final, Literal, TypeAlias

from litellm._logging import verbose_proxy_logger

Decision: TypeAlias = Literal["allowed", "denied", "unreachable"]
DEFAULT_CAPACITY: Final = 10_000


@dataclass(frozen=True, slots=True)
class AuditEvent:
    at: datetime
    actor: str
    actor_email: str | None
    dataplane_id: str
    method: str
    path: str
    decision: Decision
    status: int | None
    credential: str | None
    detail: str | None


def utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class AuditLog:
    events: deque[AuditEvent]  # mutable-ok: a bounded ring buffer of events is the whole point
    now: Callable[[], datetime] = utc_now

    def record(
        self,
        actor: str,
        actor_email: str | None,
        dataplane_id: str,
        method: str,
        path: str,
        decision: Decision,
        status: int | None = None,
        credential: str | None = None,
        detail: str | None = None,
    ) -> AuditEvent:
        event: Final = AuditEvent(
            at=self.now(),
            actor=actor,
            actor_email=actor_email,
            dataplane_id=dataplane_id,
            method=method,
            path=path,
            decision=decision,
            status=status,
            credential=credential,
            detail=detail,
        )
        self.events.append(event)
        verbose_proxy_logger.info("control_plane.audit %s", json.dumps(asdict(event), default=str))
        return event

    def recent(self, limit: int, dataplane_id: str | None = None, actor: str | None = None) -> tuple[AuditEvent, ...]:
        newest_first: Final = reversed(self.events)
        matching: Final = (
            event
            for event in newest_first
            if (dataplane_id is None or event.dataplane_id == dataplane_id) and (actor is None or event.actor == actor)
        )
        return tuple(event for _, event in zip(range(limit), matching, strict=False))


def build_audit_log(capacity: int = DEFAULT_CAPACITY, now: Callable[[], datetime] = utc_now) -> AuditLog:
    return AuditLog(events=deque(maxlen=capacity), now=now)
