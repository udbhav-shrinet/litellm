from pydantic import ConfigDict, Field

from litellm.types.llms.base import LiteLLMBaseModel


class LoginRequest(LiteLLMBaseModel):
    model_config = ConfigDict(frozen=True)

    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class SessionTokenResponse(LiteLLMBaseModel):
    model_config = ConfigDict(frozen=True)

    access_token: str
    token_type: str = "bearer"
    expires_in: int


class PrincipalResponse(LiteLLMBaseModel):
    model_config = ConfigDict(frozen=True)

    subject: str
    email: str | None
    roles: tuple[str, ...]
    scopes: tuple[str, ...]
    dataplanes: tuple[str, ...] | None
    token_kind: str
