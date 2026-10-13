import pytest

from litellm.proxy.control_plane.proxy.allowlist import Allowed, Denied, decide


@pytest.mark.parametrize(
    "path",
    [
        "/key/generate",
        "key/list",
        "/team/new",
        "/user/info",
        "/model/info",
        "/management/v1/keys",
        "/audit",
        "/spend/logs",
    ],
)
def test_management_routes_are_allowed_with_a_normalised_leading_slash(path) -> None:
    assert decide(path) == Allowed("/" + path.lstrip("/"))


@pytest.mark.parametrize(
    ("path", "fragment"),
    [
        ("/v1/chat/completions", "inference"),
        ("/chat/completions", "inference"),
        ("/v1/embeddings", "inference"),
        ("/v1/messages", "inference"),
        ("/mcp/tools/call", "inference"),
        ("/login", "auth bootstrap"),
        ("/sso/key/generate", "auth bootstrap"),
        ("/key/generate/service_account", "auth bootstrap"),
        ("/config/yaml", "auth bootstrap"),
        ("/key/../config/yaml", "traversal"),
        ("/key//info", "traversal"),
    ],
)
def test_inference_auth_and_traversal_are_denied(path, fragment) -> None:
    decision = decide(path)
    assert isinstance(decision, Denied), f"{path} was allowed"
    assert fragment in decision.reason
