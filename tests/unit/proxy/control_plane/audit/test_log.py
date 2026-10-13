from datetime import UTC, datetime, timedelta
from itertools import count

from litellm.proxy.control_plane.audit.log import build_audit_log

T0 = datetime(2026, 10, 13, 12, 0, tzinfo=UTC)


def _ticking():
    ticks = count()
    return lambda: T0 + timedelta(seconds=next(ticks))


def test_recent_is_newest_first_filtered_and_limited() -> None:
    audit = build_audit_log(capacity=10, now=_ticking())
    audit.record("alice", None, "eu", "GET", "/key/list", "allowed", 200, "service_token")
    audit.record("bob", "bob@x.test", "us", "POST", "/key/generate", "allowed", 200, "oidc_exchange")
    audit.record("alice", None, "us", "DELETE", "/key/delete", "denied", detail="nope")
    assert [(e.actor, e.path) for e in audit.recent(10)] == [
        ("alice", "/key/delete"),
        ("bob", "/key/generate"),
        ("alice", "/key/list"),
    ]
    assert [e.path for e in audit.recent(10, dataplane_id="us", actor="alice")] == ["/key/delete"]
    assert [e.path for e in audit.recent(1)] == ["/key/delete"]
    assert audit.recent(10)[0].at == T0 + timedelta(seconds=2)


def test_the_ring_buffer_drops_the_oldest_event_at_capacity() -> None:
    audit = build_audit_log(capacity=2, now=_ticking())
    for path in ("/a", "/b", "/c"):
        audit.record("alice", None, "eu", "GET", path, "allowed", 200)
    assert [e.path for e in audit.recent(10)] == ["/c", "/b"]
