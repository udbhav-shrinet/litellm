from datetime import timedelta
from typing import Annotated, Final

from fastapi import FastAPI, Security
from fastapi.testclient import TestClient

from litellm.proxy.control_plane.auth.dependencies import get_token_verifier, require_scopes
from litellm.proxy.control_plane.auth.jwt import SessionTokenCodec, TokenVerifier
from litellm.proxy.control_plane.auth.rbac import ADMIN_ROLE, VIEWER_ROLE, Principal, build_principal, default_policy
from litellm.proxy.control_plane.common.problems import install_problem_handlers

MASTER_KEY: Final = "sk-master"
POLICY: Final = default_policy()


def _app() -> tuple[TestClient, SessionTokenCodec]:
    codec: Final = SessionTokenCodec(MASTER_KEY, "cp", timedelta(hours=1), POLICY)
    app: Final = FastAPI()
    verifier: Final = TokenVerifier(MASTER_KEY, codec, None, POLICY)
    app.dependency_overrides[get_token_verifier] = lambda: verifier
    install_problem_handlers(app)

    @app.get("/usage")
    async def usage(principal: Annotated[Principal, Security(require_scopes, scopes=["usage:read"])]) -> str:
        return principal.subject

    @app.post("/dataplanes")
    async def write(principal: Annotated[Principal, Security(require_scopes, scopes=["dataplanes:write"])]) -> str:
        return principal.subject

    return TestClient(app), codec


def _token(codec: SessionTokenCodec, role: str) -> dict[str, str]:
    principal: Final = build_principal(POLICY, "u", None, frozenset({role}), frozenset(), frozenset(), "session")
    return {"Authorization": f"Bearer {codec.mint(principal)}"}


def test_viewer_reads_usage_but_cannot_write_dataplanes() -> None:
    client, codec = _app()
    assert client.get("/usage", headers=_token(codec, VIEWER_ROLE)).status_code == 200
    denied = client.post("/dataplanes", headers=_token(codec, VIEWER_ROLE))
    assert denied.status_code == 403
    assert denied.json()["detail"] == "Missing scope: dataplanes:write."
    assert denied.headers["content-type"] == "application/problem+json"


def test_admin_passes_both_scope_gates() -> None:
    client, codec = _app()
    assert client.post("/dataplanes", headers=_token(codec, ADMIN_ROLE)).status_code == 200


def test_security_scopes_show_up_in_openapi() -> None:
    client, _ = _app()
    security: Final = client.get("/openapi.json").json()["paths"]["/usage"]["get"]["security"]
    assert security == [{"ControlPlaneBearer": ["usage:read"]}]
