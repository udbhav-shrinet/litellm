"""Unit tests for claude_code_skill_access.py: key/team grant resolution."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from litellm.proxy._types import LiteLLM_ObjectPermissionTable, LitellmUserRoles, UserAPIKeyAuth
from litellm.proxy.anthropic_endpoints.claude_code_endpoints.claude_code_skill_access import (
    AccessGroupSkills,
    access_group_skills,
    granted_skills,
    resolve_skill_visibility,
    skill_visibility,
)


def _perm(skills: list[str] | None) -> LiteLLM_ObjectPermissionTable:
    return LiteLLM_ObjectPermissionTable(object_permission_id="perm", skills=skills)


def _key(key_skills: list[str] | None, team_skills: list[str] | None) -> UserAPIKeyAuth:
    return UserAPIKeyAuth(
        api_key="sk-user",
        user_role=LitellmUserRoles.INTERNAL_USER,
        object_permission=_perm(key_skills) if key_skills is not None else None,
        team_object_permission=_perm(team_skills) if team_skills is not None else None,
    )


def _plugin(name: str, enabled: bool) -> MagicMock:
    record = MagicMock()
    record.name = name
    record.enabled = enabled
    return record


@pytest.mark.parametrize(
    ("key_skills", "team_skills", "expected"),
    [
        (None, None, frozenset()),
        ([], [], frozenset()),
        (["a", "b"], None, frozenset({"a", "b"})),
        (None, ["a", "b"], frozenset({"a", "b"})),
        (["a", "b"], ["b", "c"], frozenset({"b"})),
        (["a"], ["c"], frozenset()),
        (["a", "b"], [], frozenset({"a", "b"})),
        ([], ["a", "b"], frozenset({"a", "b"})),
    ],
)
def test_granted_skills_intersects_key_with_team(key_skills, team_skills, expected):
    assert granted_skills(_key(key_skills, team_skills)) == expected


def test_visibility_enabled_plugin_is_public_for_everyone():
    public = _plugin("public-skill", enabled=True)

    assert skill_visibility(None).allows(public)
    assert skill_visibility(_key(None, None)).allows(public)
    assert skill_visibility(_key([], ["other"])).allows(public)


def test_visibility_disabled_plugin_needs_grant_or_admin():
    private = _plugin("private-skill", enabled=False)
    admin = UserAPIKeyAuth(api_key="sk-9876", user_role=LitellmUserRoles.PROXY_ADMIN)

    assert not skill_visibility(None).allows(private)
    assert not skill_visibility(_key(None, None)).allows(private)
    assert not skill_visibility(_key(["other-skill"], None)).allows(private)
    assert not skill_visibility(_key(["private-skill"], ["other-skill"])).allows(private)
    assert skill_visibility(_key(["private-skill"], None)).allows(private)
    assert skill_visibility(_key(None, ["private-skill"])).allows(private)
    assert skill_visibility(admin).allows(private)


def test_where_clause_bounds_the_plugin_query_to_what_the_caller_may_see():
    admin = UserAPIKeyAuth(api_key="sk-9876", user_role=LitellmUserRoles.PROXY_ADMIN)

    assert skill_visibility(None).where() == {"enabled": True}
    assert skill_visibility(_key(None, None)).where() == {"enabled": True}
    assert skill_visibility(_key(["b", "a"], None)).where() == {"OR": [{"enabled": True}, {"name": {"in": ["a", "b"]}}]}
    assert skill_visibility(_key(["a", "b"], ["b"])).where() == {"OR": [{"enabled": True}, {"name": {"in": ["b"]}}]}
    assert skill_visibility(admin).where() == {}


@pytest.mark.parametrize(
    ("key_skills", "team_skills", "inherited", "expected"),
    [
        (None, None, AccessGroupSkills(key=frozenset({"g"})), frozenset({"g"})),
        (None, None, AccessGroupSkills(team=frozenset({"g"})), frozenset({"g"})),
        (None, None, AccessGroupSkills(), frozenset()),
        ([], [], AccessGroupSkills(key=frozenset({"g1"}), team=frozenset({"g2"})), frozenset()),
        (["a"], None, AccessGroupSkills(key=frozenset({"g"})), frozenset({"a", "g"})),
        (None, ["a"], AccessGroupSkills(team=frozenset({"g"})), frozenset({"a", "g"})),
        (None, ["a"], AccessGroupSkills(key=frozenset({"g"})), frozenset()),
        (["a"], ["a", "b"], AccessGroupSkills(key=frozenset({"b"})), frozenset({"a", "b"})),
        (["a"], ["a"], AccessGroupSkills(key=frozenset({"g"}), team=frozenset({"g"})), frozenset({"a", "g"})),
    ],
)
def test_granted_skills_adds_access_group_skills_to_their_own_scope_before_intersecting(
    key_skills, team_skills, inherited, expected
):
    assert granted_skills(_key(key_skills, team_skills), inherited) == expected


def test_visibility_with_inherited_skills_only_opens_the_inherited_private_plugin():
    inherited = AccessGroupSkills(key=frozenset({"group-skill"}))
    visibility = skill_visibility(_key(None, None), inherited)

    assert visibility.allows(_plugin("group-skill", enabled=False))
    assert not visibility.allows(_plugin("other-private", enabled=False))
    assert visibility.allows(_plugin("public", enabled=True))
    assert visibility.where() == {"OR": [{"enabled": True}, {"name": {"in": ["group-skill"]}}]}


@pytest.mark.asyncio
async def test_resolve_skill_visibility_folds_in_access_group_skills_for_non_admins():
    loader = AsyncMock(return_value=AccessGroupSkills(team=frozenset({"group-skill"})))
    caller = _key(None, None)

    visibility = await resolve_skill_visibility(caller, loader)

    loader.assert_awaited_once_with(caller)
    assert visibility.allows(_plugin("group-skill", enabled=False))
    assert not visibility.allows(_plugin("other-private", enabled=False))


@pytest.mark.asyncio
async def test_resolve_skill_visibility_skips_group_lookup_for_anonymous_and_admin_callers():
    loader = AsyncMock(return_value=AccessGroupSkills(key=frozenset({"group-skill"})))
    admin = UserAPIKeyAuth(api_key="sk-9876", user_role=LitellmUserRoles.PROXY_ADMIN)

    assert not (await resolve_skill_visibility(None, loader)).allows(_plugin("group-skill", enabled=False))
    assert (await resolve_skill_visibility(admin, loader)).sees_private
    loader.assert_not_awaited()


def _team(team_id: str, access_group_ids: list[str], blocked: bool = False) -> MagicMock:
    team = MagicMock()
    team.team_id = team_id
    team.access_group_ids = access_group_ids
    team.blocked = blocked
    return team


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("team_blocked", "expected_team_skills"),
    [(False, frozenset({"team-group-skill"})), (True, frozenset())],
)
async def test_access_group_skills_resolves_key_groups_and_team_groups(monkeypatch, team_blocked, expected_team_skills):
    from litellm.proxy import proxy_server
    from litellm.proxy.auth import auth_checks

    groups = {
        "key-group": frozenset({"key-group-skill"}),
        "team-group": frozenset({"team-group-skill"}),
    }

    async def fake_skill_names(access_group_ids, **_kwargs):
        return frozenset().union(*(groups[group_id] for group_id in access_group_ids))

    monkeypatch.setattr(auth_checks, "get_skill_names_from_access_groups", fake_skill_names)
    monkeypatch.setattr(
        auth_checks, "get_team_object", AsyncMock(return_value=_team("team-1", ["team-group"], blocked=team_blocked))
    )
    monkeypatch.setattr(proxy_server, "prisma_client", MagicMock())
    caller = UserAPIKeyAuth(
        api_key="sk-user",
        user_role=LitellmUserRoles.INTERNAL_USER,
        team_id="team-1",
        access_group_ids=["key-group"],
    )

    inherited = await access_group_skills(caller)

    assert inherited == AccessGroupSkills(key=frozenset({"key-group-skill"}), team=expected_team_skills)


@pytest.mark.asyncio
async def test_access_group_skills_without_groups_or_team_grants_nothing(monkeypatch):
    from litellm.proxy import proxy_server
    from litellm.proxy.auth import auth_checks

    get_team_object = AsyncMock()
    monkeypatch.setattr(auth_checks, "get_team_object", get_team_object)
    monkeypatch.setattr(auth_checks, "get_skill_names_from_access_groups", AsyncMock(return_value=frozenset()))
    monkeypatch.setattr(proxy_server, "prisma_client", MagicMock())
    caller = UserAPIKeyAuth(api_key="sk-user", user_role=LitellmUserRoles.INTERNAL_USER)

    assert await access_group_skills(caller) == AccessGroupSkills()
    get_team_object.assert_not_awaited()
