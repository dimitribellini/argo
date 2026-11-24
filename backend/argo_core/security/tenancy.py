"""Opt-in Multi-User ownership, Team Group visibility, and admin RBAC helpers."""

from __future__ import annotations

import re
from typing import Any, Literal

VALID_VISIBILITIES: frozenset[str] = frozenset({"private", "team", "shared"})


def normalize_email(email: str | None) -> str:
    """Normalize an SSO or local account email identity for tenancy comparisons."""
    cleaned = str(email or "").strip().lower()
    if cleaned in {"", "operator@local"}:
        return ""
    return cleaned


def normalize_visibility(value: str | None, *, default: str = "shared") -> str:
    """Validate and normalize visibility ('private' | 'team' | 'shared')."""
    if value is None or not str(value).strip():
        return default if default in VALID_VISIBILITIES else "shared"
    cleaned = str(value).strip().lower()
    if cleaned not in VALID_VISIBILITIES:
        raise ValueError(
            f"Invalid visibility '{value}'; expected 'private', 'team', or 'shared'."
        )
    return cleaned


def normalize_group_slugs(raw: Any) -> list[str]:
    """Normalize and deduplicate Team Group slug lists."""
    if not raw or not isinstance(raw, (list, tuple, set)):
        return []
    seen: set[str] = set()
    cleaned: list[str] = []
    for item in raw:
        slug = re.sub(r"[^a-z0-9]+", "-", str(item or "").strip().lower()).strip("-")
        if slug and slug not in seen:
            seen.add(slug)
            cleaned.append(slug)
    return cleaned


def resolved_auth_mode_for_settings(settings: Any) -> str:
    """Return resolved auth mode ('sso' | 'local' | 'hybrid') safely."""
    fn = getattr(settings, "resolved_auth_mode", None)
    if callable(fn):
        return str(fn())
    return "sso"


def is_multi_user_enabled(settings: Any) -> bool:
    """Return True when opt-in multi-user resource ACL isolation is active."""
    return bool(getattr(settings, "multi_user", False))


def is_auth_rbac_active(settings: Any) -> bool:
    """Return True when admin RBAC should be enforced (multi-user or local/hybrid auth)."""
    return is_multi_user_enabled(settings) or resolved_auth_mode_for_settings(settings) in {
        "local",
        "hybrid",
    }


def is_workspace_admin(email: str | None, settings: Any, *, repo: Any = None) -> bool:
    """Return True in single-user SSO mode or if caller is an active admin."""
    if not is_auth_rbac_active(settings):
        return True
    clean_email = normalize_email(email)
    if not clean_email:
        return False
    raw_admins = getattr(settings, "admin_emails", ()) or ()
    admins = {normalize_email(str(a)) for a in raw_admins if normalize_email(str(a))}
    if clean_email in admins:
        return True
    if repo is not None:
        user = repo.get_user(clean_email)
        if user is not None and user.get("active", True) and user.get("role") == "admin":
            return True
    return False


def user_group_slugs(email: str | None, *, repo: Any = None) -> set[str]:
    """Return all Team Group slugs that include the normalized user email."""
    clean_email = normalize_email(email)
    if repo is None or not clean_email:
        return set()
    out: set[str] = set()
    for group in repo.list_team_groups():
        members = {normalize_email(str(m)) for m in (group.get("member_emails") or [])}
        if clean_email in members:
            gslug = str(group.get("slug") or "").strip()
            if gslug:
                out.add(gslug)
    return out


def effective_user_container_quota(
    email: str | None,
    settings: Any,
    *,
    kind: Literal["desktop", "sandbox"],
    repo: Any = None,
) -> int:
    """Return effective active container cap honoring per-user admin overrides."""
    default_cap = int(
        getattr(
            settings,
            "max_active_desktops_per_user" if kind == "desktop" else "max_active_sandboxes_per_user",
            2 if kind == "desktop" else 4,
        )
        or 0
    )
    clean_email = normalize_email(email)
    if repo is not None and clean_email:
        user = repo.get_user(clean_email)
        if user is not None:
            field = "max_active_desktops" if kind == "desktop" else "max_active_sandboxes"
            override = user.get(field)
            if override is not None:
                try:
                    return max(0, int(override))
                except (TypeError, ValueError):
                    pass
    return max(0, default_cap)


def default_visibility_for_new(settings: Any, requested: str | None = None) -> str:
    """Default newly created resources to 'private' in multi-user mode unless specified."""
    default = "private" if is_multi_user_enabled(settings) else "shared"
    return normalize_visibility(requested, default=default)


def can_read_resource(
    caller_email: str | None,
    *,
    owner_email: str | None,
    visibility: str | None,
    allowed_groups: list[str] | set[str] | None = None,
    caller_groups: set[str] | list[str] | None = None,
    settings: Any,
    repo: Any = None,
) -> bool:
    """Return True if caller may inspect or interact with the resource."""
    if not is_multi_user_enabled(settings):
        return True
    if is_workspace_admin(caller_email, settings, repo=repo):
        return True
    vis = normalize_visibility(visibility, default="shared")
    if vis == "shared":
        return True
    clean_owner = normalize_email(owner_email)
    clean_caller = normalize_email(caller_email)
    if vis == "team":
        if clean_owner and clean_caller == clean_owner:
            return True
        target_groups = set(normalize_group_slugs(list(allowed_groups or [])))
        if not target_groups or not clean_caller:
            return False
        my_groups = (
            set(caller_groups)
            if caller_groups is not None
            else user_group_slugs(clean_caller, repo=repo)
        )
        return bool(target_groups & my_groups)
    if not clean_owner:
        return True
    return bool(clean_caller and clean_caller == clean_owner)


def can_manage_resource(
    caller_email: str | None,
    *,
    owner_email: str | None,
    visibility: str | None,
    settings: Any,
    repo: Any = None,
) -> bool:
    """Return True if caller may mutate, configure, or delete the resource."""
    del visibility
    if not is_multi_user_enabled(settings):
        return True
    if is_workspace_admin(caller_email, settings, repo=repo):
        return True
    clean_owner = normalize_email(owner_email)
    if not clean_owner:
        return False
    clean_caller = normalize_email(caller_email)
    return bool(clean_caller and clean_caller == clean_owner)


def is_scope_subset(
    child_vis: str | None,
    child_groups: list[str] | set[str] | None,
    parent_vis: str | None,
    parent_groups: list[str] | set[str] | None,
    *,
    child_owner: str | None = "",
    parent_owner: str | None = "",
    settings: Any,
    repo: Any = None,
) -> bool:
    """Ensure a child bot/room/page never leaks a narrower resource to a broader audience."""
    if not is_multi_user_enabled(settings):
        return True
    p_vis = normalize_visibility(parent_vis, default="shared")
    c_vis = normalize_visibility(child_vis, default="shared")
    p_groups = set(normalize_group_slugs(list(parent_groups or [])))
    c_groups = set(normalize_group_slugs(list(child_groups or [])))
    clean_parent_owner = normalize_email(parent_owner)

    if p_vis == "shared":
        return True
    if p_vis == "private" and not clean_parent_owner:
        return True
    if c_vis == "shared":
        return False
    if c_vis == "team":
        if p_vis != "team":
            return False
        return bool(c_groups) and c_groups.issubset(p_groups)
    # Private bot/room/page: permitted if its owner can read the parent resource
    return can_read_resource(
        child_owner,
        owner_email=clean_parent_owner,
        visibility=p_vis,
        allowed_groups=p_groups,
        settings=settings,
        repo=repo,
    )


def enrich_principal(principal: dict[str, Any], settings: Any, *, repo: Any = None) -> dict[str, Any]:
    """Attach auth mode, admin flag, team memberships, and container quota limits to /api/me."""
    email = str(principal.get("email") or "").strip()
    clean_email = normalize_email(email)
    user_rec = repo.get_user(clean_email) if (repo is not None and clean_email) else None
    groups_info: list[dict[str, str]] = []
    if repo is not None and clean_email:
        for grp in repo.list_team_groups():
            members = {normalize_email(str(m)) for m in (grp.get("member_emails") or [])}
            if clean_email in members:
                groups_info.append({"slug": str(grp["slug"]), "name": str(grp["name"])})
    return {
        **principal,
        "display_name": (
            str(user_rec.get("display_name") or "")
            if user_rec
            else str(principal.get("display_name") or "")
        ),
        "must_change_password": bool(
            user_rec.get("must_change_password", False)
            if user_rec
            else principal.get("must_change_password", False)
        ),
        "auth_method": str(
            principal.get("auth_method")
            or ("sso" if resolved_auth_mode_for_settings(settings) == "sso" else "password")
        ),
        "auth_mode": resolved_auth_mode_for_settings(settings),
        "google_auth_enabled": bool(
            callable(getattr(settings, "google_auth_configured", None))
            and settings.google_auth_configured()
        ),
        "is_admin": is_workspace_admin(email, settings, repo=repo),
        "multi_user": is_multi_user_enabled(settings),
        "groups": groups_info,
        "max_active_desktops_per_user": effective_user_container_quota(
            email, settings, kind="desktop", repo=repo
        ),
        "max_active_sandboxes_per_user": effective_user_container_quota(
            email, settings, kind="sandbox", repo=repo
        ),
    }
