import pytest

from litellm.proxy._types import LiteLLM_UserTable, LitellmUserRoles
from litellm.proxy.auth.impersonation import (
    IMPERSONATE_EMAIL_HEADER,
    IMPERSONATE_USER_HEADER,
    ImpersonatedUserNotFound,
    ImpersonationForbidden,
    ImpersonationRequest,
    impersonate,
    read_impersonation_request,
)
from litellm.types.proxy.auth.user_api_key_auth import UserAPIKeyAuth

ALICE = LiteLLM_UserTable(user_id="alice", user_email="alice@x.test", user_role=LitellmUserRoles.PROXY_ADMIN.value)


def _service_key(permissions: dict[str, object]) -> UserAPIKeyAuth:
    return UserAPIKeyAuth(
        api_key="hashed",
        token="hashed",
        key_alias="control-plane",
        user_id="svc",
        team_id="platform",
        permissions=permissions,
    )


async def _directory(user_id: str, user_email: str | None) -> LiteLLM_UserTable | None:
    return ALICE if user_id == "alice" or user_email == "alice@x.test" else None


def test_headers_without_a_user_are_not_an_impersonation_request() -> None:
    assert read_impersonation_request({}) is None
    assert read_impersonation_request({IMPERSONATE_USER_HEADER: "  ", IMPERSONATE_EMAIL_HEADER: "a@x"}) is None


def test_headers_parse_user_and_optional_email() -> None:
    assert read_impersonation_request({IMPERSONATE_USER_HEADER: "alice"}) == ImpersonationRequest("alice", None)
    assert read_impersonation_request({IMPERSONATE_USER_HEADER: "alice", IMPERSONATE_EMAIL_HEADER: "a@x"}) == (
        ImpersonationRequest("alice", "a@x")
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("permissions", [{}, {"impersonate": False}, {"impersonate": "true"}])
async def test_key_without_the_permission_is_forbidden(permissions: dict[str, object]) -> None:
    result = await impersonate(_service_key(permissions), ImpersonationRequest("alice", None), _directory)
    assert isinstance(result, ImpersonationForbidden)
    assert "control-plane" in result.detail


@pytest.mark.asyncio
async def test_unknown_subject_is_not_found_not_created() -> None:
    result = await impersonate(_service_key({"impersonate": True}), ImpersonationRequest("ghost", None), _directory)
    assert result == ImpersonatedUserNotFound("ghost")


@pytest.mark.asyncio
async def test_permitted_key_becomes_the_subject_and_records_the_actor() -> None:
    result = await impersonate(_service_key({"impersonate": True}), ImpersonationRequest("alice", None), _directory)
    assert isinstance(result, UserAPIKeyAuth)
    assert (result.user_id, result.user_email, result.user_role) == (
        "alice",
        "alice@x.test",
        LitellmUserRoles.PROXY_ADMIN,
    )
    assert result.impersonated_by == "control-plane"
    assert (result.api_key, result.team_id) == ("hashed", "platform")
