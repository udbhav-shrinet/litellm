"""Kubernetes-style impersonation for service keys: a key with the `impersonate` permission acts as a named user."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Protocol, TypeAlias

from pydantic import BaseModel, ConfigDict

from litellm.proxy._types import LiteLLM_UserTable, LitellmUserRoles
from litellm.proxy.auth.auth_checks import get_user_role
from litellm.types.proxy.auth.user_api_key_auth import UserAPIKeyAuth

IMPERSONATE_USER_HEADER: Final = "X-LiteLLM-Impersonate-User"
IMPERSONATE_EMAIL_HEADER: Final = "X-LiteLLM-Impersonate-Email"
IMPERSONATE_PERMISSION: Final = "impersonate"


@dataclass(frozen=True, slots=True)
class ImpersonationRequest:
    user_id: str
    email: str | None


@dataclass(frozen=True, slots=True)
class ImpersonationForbidden:
    detail: str


@dataclass(frozen=True, slots=True)
class ImpersonatedUserNotFound:
    user_id: str


ImpersonationError: TypeAlias = ImpersonationForbidden | ImpersonatedUserNotFound


class _KeyPermissions(BaseModel):
    """Typed view of the key's `permissions` JSON column, read off the auth object by attribute."""

    model_config = ConfigDict(frozen=True, from_attributes=True, extra="ignore")

    permissions: Mapping[str, object] = {}


class UserLookup(Protocol):
    async def __call__(self, user_id: str, user_email: str | None) -> LiteLLM_UserTable | None: ...


def read_impersonation_request(headers: Mapping[str, str]) -> ImpersonationRequest | None:
    user_id: Final = headers.get(IMPERSONATE_USER_HEADER, "").strip()
    email: Final = headers.get(IMPERSONATE_EMAIL_HEADER, "").strip()
    if not user_id:
        return None
    return ImpersonationRequest(user_id=user_id, email=email or None)


def key_may_impersonate(permissions: Mapping[str, object]) -> bool:
    return permissions.get(IMPERSONATE_PERMISSION) is True


def actor_label(actor: UserAPIKeyAuth) -> str:
    return actor.key_alias or actor.token or "unknown-key"


async def impersonate(
    actor: UserAPIKeyAuth,
    request: ImpersonationRequest,
    lookup: UserLookup,
) -> UserAPIKeyAuth | ImpersonationError:
    if not key_may_impersonate(_KeyPermissions.model_validate(actor).permissions):
        return ImpersonationForbidden(f"key {actor_label(actor)} lacks the {IMPERSONATE_PERMISSION!r} permission")
    subject: Final = await lookup(request.user_id, request.email)
    if subject is None:
        return ImpersonatedUserNotFound(request.user_id)
    return actor.model_copy(
        update={
            "user_id": subject.user_id,
            "user_email": subject.user_email,
            "user_role": get_user_role(subject) or LitellmUserRoles.INTERNAL_USER,
            "impersonated_by": actor_label(actor),
        }
    )
