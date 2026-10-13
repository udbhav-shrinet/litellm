"""Which dataplane routes the passthrough may carry. Management only, never auth bootstrap or inference."""

from dataclasses import dataclass
from typing import Final

MANAGEMENT_PREFIXES: Final = (
    "/key/",
    "/v2/key/",
    "/user/",
    "/v2/user/",
    "/team/",
    "/v2/team/",
    "/organization/",
    "/v2/organization/",
    "/customer/",
    "/end_user/",
    "/budget/",
    "/tag/",
    "/model/",
    "/v1/model/info",
    "/v2/model/",
    "/model_group/",
    "/model_access_group/",
    "/access_group/",
    "/credentials",
    "/credential",
    "/guardrails/",
    "/v2/guardrails/",
    "/v1/mcp/server",
    "/vector_store/",
    "/spend/",
    "/global/spend",
    "/user/daily/activity",
    "/team/daily/activity",
    "/tag/daily/activity",
    "/audit",
    "/management/v1/",
    "/health",
    "/active/callbacks",
    "/callbacks",
    "/alerting/",
    "/router_settings",
    "/settings",
)

DENIED_PREFIXES: Final = (
    "/login",
    "/logout",
    "/sso/",
    "/token",
    "/jwt/",
    "/oauth/",
    "/invitation/",
    "/onboarding/",
    "/session/",
    "/key/generate/service_account",
    "/config/",
    "/debug/",
    "/utils/",
)


@dataclass(frozen=True, slots=True)
class Allowed:
    path: str


@dataclass(frozen=True, slots=True)
class Denied:
    path: str
    reason: str


def decide(raw_path: str) -> Allowed | Denied:
    path: Final = "/" + raw_path.lstrip("/")
    if ".." in path.split("/") or "//" in path:
        return Denied(path, "path traversal is not allowed")
    if any(path.startswith(prefix) for prefix in DENIED_PREFIXES):
        return Denied(path, "auth bootstrap and debug routes never go through the control plane")
    if not any(path.startswith(prefix) for prefix in MANAGEMENT_PREFIXES):
        return Denied(path, "only management routes are proxied, inference goes straight to the dataplane")
    return Allowed(path)
