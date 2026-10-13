"""Username and password login for the admin configured through UI_USERNAME / UI_PASSWORD."""

import secrets
from typing import Final

from litellm.proxy.control_plane.auth.jwt import SessionTokenCodec
from litellm.proxy.control_plane.auth.rbac import ADMIN_ROLE, RolePolicy, build_principal
from litellm.types.proxy.control_plane.auth import SessionTokenResponse


class LoginService:
    def __init__(
        self,
        sessions: SessionTokenCodec,
        policy: RolePolicy,
        ttl_seconds: int,
        admin_username: str | None,
        admin_password: str | None,
    ) -> None:
        self._sessions = sessions
        self._policy = policy
        self._ttl_seconds = ttl_seconds
        self._admin_username = admin_username
        self._admin_password = admin_password

    def login(self, username: str, password: str) -> SessionTokenResponse | None:
        if self._admin_username is None or self._admin_password is None:
            return None
        username_ok: Final = secrets.compare_digest(username, self._admin_username)
        password_ok: Final = secrets.compare_digest(password, self._admin_password)
        if not (username_ok and password_ok):
            return None
        principal: Final = build_principal(
            policy=self._policy,
            subject=self._admin_username,
            email=None,
            roles=frozenset({ADMIN_ROLE}),
            claimed_scopes=frozenset(),
            dataplane_ids=frozenset(),
            token_kind="session",
        )
        return SessionTokenResponse(access_token=self._sessions.mint(principal), expires_in=self._ttl_seconds)
