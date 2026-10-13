import pytest

from litellm.litellm_core_utils.oauth_token_exchange import OAuthTokenExchangeConfig, OAuthTokenExchangeError
from litellm.proxy.auth.impersonation import IMPERSONATE_EMAIL_HEADER, IMPERSONATE_USER_HEADER
from litellm.proxy.control_plane.dataplanes.credentials import (
    CredentialChain,
    CredentialUnavailable,
    IssuedCredential,
    OidcTokenExchange,
    ServiceTokenImpersonation,
)
from tests.unit.proxy.control_plane.dataplanes.conftest import caller


async def _exchange(config: OAuthTokenExchangeConfig, subject_token: str) -> str:
    return f"exchanged({subject_token})->{config.audience}"


async def _failing_exchange(config: OAuthTokenExchangeConfig, subject_token: str) -> str:
    raise OAuthTokenExchangeError(status_code=401, message="nope")


@pytest.mark.asyncio
async def test_service_token_asserts_the_caller_in_impersonation_headers() -> None:
    issued = await ServiceTokenImpersonation("sk-svc").headers(caller("session"))
    assert issued == IssuedCredential(
        "service_token",
        {"Authorization": "Bearer sk-svc", IMPERSONATE_USER_HEADER: "alice", IMPERSONATE_EMAIL_HEADER: "alice@x.test"},
    )


@pytest.mark.asyncio
async def test_master_key_caller_uses_the_service_token_as_itself() -> None:
    issued = await ServiceTokenImpersonation("sk-svc").headers(caller("master_key"))
    assert isinstance(issued, IssuedCredential)
    assert dict(issued.headers) == {"Authorization": "Bearer sk-svc"}


@pytest.mark.asyncio
async def test_oidc_exchange_needs_an_idp_token(exchange_config: OAuthTokenExchangeConfig) -> None:
    result = await OidcTokenExchange(exchange_config, _exchange).headers(caller("session"))
    assert isinstance(result, CredentialUnavailable) and result.kind == "oidc_exchange"
    assert "session" in result.reason


@pytest.mark.asyncio
async def test_oidc_exchange_trades_the_callers_bearer_for_a_dataplane_token(
    exchange_config: OAuthTokenExchangeConfig,
) -> None:
    issued = await OidcTokenExchange(exchange_config, _exchange).headers(caller("oidc", "idp-token"))
    assert issued == IssuedCredential("oidc_exchange", {"Authorization": "Bearer exchanged(idp-token)->dp"})


@pytest.mark.asyncio
async def test_failed_exchange_is_a_value_with_the_idp_status(exchange_config: OAuthTokenExchangeConfig) -> None:
    result = await OidcTokenExchange(exchange_config, _failing_exchange).headers(caller("oidc"))
    assert result == CredentialUnavailable("oidc_exchange", "token exchange failed with status 401")


@pytest.mark.asyncio
async def test_chain_falls_back_to_the_service_token_when_exchange_cannot_serve_the_caller(
    exchange_config: OAuthTokenExchangeConfig,
) -> None:
    chain = CredentialChain((OidcTokenExchange(exchange_config, _exchange), ServiceTokenImpersonation("sk-svc")))
    assert chain.kinds == ("oidc_exchange", "service_token")
    via_session = await chain.headers(caller("session"))
    via_oidc = await chain.headers(caller("oidc"))
    assert isinstance(via_session, IssuedCredential) and via_session.kind == "service_token"
    assert isinstance(via_oidc, IssuedCredential) and via_oidc.kind == "oidc_exchange"


@pytest.mark.asyncio
async def test_chain_reports_every_failure_when_nothing_can_authenticate(
    exchange_config: OAuthTokenExchangeConfig,
) -> None:
    result = await CredentialChain((OidcTokenExchange(exchange_config, _failing_exchange),)).headers(caller("oidc"))
    assert isinstance(result, CredentialUnavailable)
    assert result.reason == "oidc_exchange: token exchange failed with status 401"
    assert isinstance(await CredentialChain(()).headers(caller("oidc")), CredentialUnavailable)
