import httpx

from litellm.proxy.control_plane.auth.rbac import EDITOR_ROLE, VIEWER_ROLE
from tests.unit.proxy.control_plane.support import response, rig

EU = "https://eu.test"


def test_get_is_forwarded_as_the_caller_with_query_and_the_dataplane_status_comes_back() -> None:
    client, transport, minter = rig({f"{EU}/key/list": [response(200, {"keys": ["k1"], "total_count": 1})]})
    reply = client.get("/api/v1/dataplanes/eu/proxy/key/list?page=2&size=5", headers=minter.headers("eu"))
    assert (reply.status_code, reply.json()) == (200, {"keys": ["k1"], "total_count": 1})
    assert reply.headers["X-LiteLLM-Dataplane"] == "eu"
    url, params, headers = transport.calls[0]
    assert (url, params) == (f"{EU}/key/list", {"page": "2", "size": "5"})
    assert headers is not None and headers["X-LiteLLM-Impersonate-User"] == "alice"


def test_writes_need_proxy_write_go_out_once_and_are_audited() -> None:
    client, transport, minter = rig(
        {
            f"{EU}/key/generate": [response(200, {"key": "sk-new", "token_id": "t1"})],
            f"{EU}/team/update": [httpx.ReadTimeout("slow")],
            f"{EU}/key/delete": [response(400, {"error": {"message": "no such key"}})],
        }
    )
    viewer = minter.headers("eu", role=VIEWER_ROLE)
    editor = minter.headers("eu", role=EDITOR_ROLE)
    denied = client.post("/api/v1/dataplanes/eu/proxy/key/generate", json={"key_alias": "x"}, headers=viewer)
    assert denied.status_code == 403 and "proxy:write" in denied.json()["detail"]
    created = client.post("/api/v1/dataplanes/eu/proxy/key/generate", json={"key_alias": "x"}, headers=editor)
    assert (created.status_code, created.json()["token_id"]) == (200, "t1")
    assert transport.writes == [("POST", f"{EU}/key/generate", {"key_alias": "x"})]
    timed_out = client.patch("/api/v1/dataplanes/eu/proxy/team/update", json={"team_id": "t"}, headers=editor)
    assert timed_out.status_code == 502 and "1 attempt" in timed_out.json()["detail"]
    failed = client.delete("/api/v1/dataplanes/eu/proxy/key/delete", headers=editor)
    assert (failed.status_code, failed.json()) == (400, {"error": {"message": "no such key"}})
    trail = client.get("/api/v1/audit", headers=minter.headers(role="admin")).json()["items"]
    assert [(e["method"], e["path"], e["decision"], e["status"]) for e in trail] == [
        ("DELETE", "/key/delete", "allowed", 400),
        ("PATCH", "/team/update", "unreachable", None),
        ("POST", "/key/generate", "allowed", 200),
    ]
    assert trail[2]["actor"] == "alice" and trail[2]["credential"] == "service_token"


def test_denied_paths_are_403_audited_and_never_reach_the_dataplane() -> None:
    client, transport, minter = rig({})
    blocked = client.post(
        "/api/v1/dataplanes/eu/proxy/v1/chat/completions", json={"model": "x"}, headers=minter.headers(role=EDITOR_ROLE)
    )
    assert blocked.status_code == 403 and "inference" in blocked.json()["detail"]
    assert transport.calls == []
    trail = client.get("/api/v1/audit?dataplane=eu", headers=minter.headers(role="admin")).json()["items"]
    assert [(e["path"], e["decision"]) for e in trail] == [("/v1/chat/completions", "denied")]


def test_a_non_object_body_is_400_and_unbound_dataplane_is_403() -> None:
    client, _, minter = rig({})
    bad = client.post(
        "/api/v1/dataplanes/eu/proxy/key/generate",
        content=b"[1,2]",
        headers={**minter.headers(role=EDITOR_ROLE), "Content-Type": "application/json"},
    )
    assert bad.status_code == 400
    assert client.get("/api/v1/dataplanes/us/proxy/key/list", headers=minter.headers("eu")).status_code == 403


def test_audit_read_needs_its_scope_and_filters_by_actor() -> None:
    client, _, minter = rig({f"{EU}/key/list": [response(200, {})]})
    client.get("/api/v1/dataplanes/eu/proxy/key/list", headers=minter.headers("eu"))
    assert client.get("/api/v1/audit", headers=minter.headers(role=EDITOR_ROLE)).status_code == 403
    assert client.get("/api/v1/audit?actor=bob", headers=minter.headers(role="admin")).json()["items"] == []
    assert len(client.get("/api/v1/audit?actor=alice", headers=minter.headers(role="admin")).json()["items"]) == 1
