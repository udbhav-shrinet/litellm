from typing import Annotated, Final

from fastapi import APIRouter, Depends, Security

from litellm.proxy.control_plane.auth.dependencies import require_scopes
from litellm.proxy.control_plane.auth.login import LoginService
from litellm.proxy.control_plane.auth.rbac import Principal
from litellm.proxy.control_plane.common.problems import ControlPlaneProblem, unauthorized
from litellm.types.proxy.control_plane.auth import LoginRequest, PrincipalResponse, SessionTokenResponse

router: Final = APIRouter(prefix="/auth", tags=["control plane: auth"])


def get_login_service() -> LoginService:
    raise RuntimeError("get_login_service is not bound, build the app with create_app")


def principal_response(principal: Principal) -> PrincipalResponse:
    return PrincipalResponse(
        subject=principal.subject,
        email=principal.email,
        roles=tuple(sorted(principal.roles)),
        scopes=tuple(sorted(scope.value for scope in principal.scopes)),
        dataplanes=None if principal.dataplanes.all else tuple(sorted(principal.dataplanes.ids)),
        token_kind=principal.token_kind,
    )


@router.post("/login", response_model=SessionTokenResponse)
async def login(
    body: LoginRequest,
    service: Annotated[LoginService, Depends(get_login_service)],
) -> SessionTokenResponse:
    token: Final = service.login(body.username, body.password)
    if token is None:
        raise ControlPlaneProblem(unauthorized("Invalid username or password."))
    return token


@router.get("/me", response_model=PrincipalResponse)
async def me(principal: Annotated[Principal, Security(require_scopes)]) -> PrincipalResponse:
    return principal_response(principal)
