"""Admin-only product-user management endpoints."""

from __future__ import annotations

import asyncio

import psycopg2.errors
from fastapi import APIRouter, Depends, HTTPException, Path

from otalon_api.api.schemas.admin_users import (
    DeleteUserResponse,
    OneTimePasswordResponse,
    UserCreateRequest,
    UserListResponse,
    UserPatchRequest,
    UserResponse,
)
from otalon_api.dependencies import get_session_repo, get_user_repo
from otalon_api.middleware.session_auth import require_minimum_role
from otalon_api.repositories.identity_repo import (
    LastActiveAdminError,
    SessionRepository,
    UserEntry,
    UserRepository,
    generate_bootstrap_password,
)

router = APIRouter(prefix="/api/v1/admin/users", tags=["admin-users"])
require_admin = require_minimum_role("admin")


def _user_response(user: UserEntry) -> UserResponse:
    """Convert internal user identity to a password-free API response."""
    return UserResponse(
        id=user.id,
        username=user.username,
        role=user.role,
        disabled=user.disabled,
        must_change_password=user.must_change_password,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )


def _duplicate_username(exc: psycopg2.errors.UniqueViolation) -> HTTPException:
    """Convert PostgreSQL username uniqueness failure to HTTP 409."""
    del exc
    return HTTPException(status_code=409, detail="Username already exists")


@router.get("", response_model=UserListResponse, dependencies=[Depends(require_admin)])
async def list_users(users: UserRepository = Depends(get_user_repo)) -> UserListResponse:
    """List all product users without password hashes."""
    entries = await asyncio.to_thread(users.list_users)
    return UserListResponse(users=[_user_response(entry) for entry in entries])


@router.post("", response_model=OneTimePasswordResponse, status_code=201)
async def create_user(
    body: UserCreateRequest,
    users: UserRepository = Depends(get_user_repo),
    _admin: UserEntry = Depends(require_admin),
) -> OneTimePasswordResponse:
    """Create one forced-change user and return its password once."""
    del _admin
    password = generate_bootstrap_password()
    try:
        user = await asyncio.to_thread(users.create_user, body.username, body.role, password)
    except psycopg2.errors.UniqueViolation as exc:
        raise _duplicate_username(exc) from exc
    return OneTimePasswordResponse(user=_user_response(user), one_time_password=password)


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    body: UserPatchRequest,
    user_id: int = Path(ge=1),
    users: UserRepository = Depends(get_user_repo),
    sessions: SessionRepository = Depends(get_session_repo),
    _admin: UserEntry = Depends(require_admin),
) -> UserResponse:
    """Update target role or disabled state; disabling revokes sessions."""
    del _admin
    if body.role is None and body.disabled is None:
        raise HTTPException(status_code=422, detail="At least one field is required")
    try:
        user = await asyncio.to_thread(users.update_user, user_id, body.role, body.disabled)
    except LastActiveAdminError as exc:
        raise HTTPException(status_code=409, detail="Cannot remove the last active administrator") from exc
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if body.disabled is True:
        await asyncio.to_thread(sessions.revoke_for_user, user_id)
    return _user_response(user)


@router.post("/{user_id}/reset-password", response_model=OneTimePasswordResponse)
async def reset_password(
    user_id: int = Path(ge=1),
    users: UserRepository = Depends(get_user_repo),
    sessions: SessionRepository = Depends(get_session_repo),
    _admin: UserEntry = Depends(require_admin),
) -> OneTimePasswordResponse:
    """Reset target password, revoke sessions, and return one-time password."""
    del _admin
    password = generate_bootstrap_password()
    updated = await asyncio.to_thread(users.reset_password, user_id, password)
    if not updated:
        raise HTTPException(status_code=404, detail="User not found")
    await asyncio.to_thread(sessions.revoke_for_user, user_id)
    target = await asyncio.to_thread(users.find_by_id, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    return OneTimePasswordResponse(user=_user_response(target), one_time_password=password)


@router.delete("/{user_id}", response_model=DeleteUserResponse)
async def delete_user(
    user_id: int = Path(ge=1),
    users: UserRepository = Depends(get_user_repo),
    sessions: SessionRepository = Depends(get_session_repo),
    admin: UserEntry = Depends(require_admin),
) -> DeleteUserResponse:
    """Delete another user and revoke all target sessions."""
    if user_id == admin.id:
        raise HTTPException(status_code=403, detail="Administrators cannot delete themselves")
    try:
        deleted = await asyncio.to_thread(users.delete_user, user_id)
    except LastActiveAdminError as exc:
        raise HTTPException(status_code=409, detail="Cannot remove the last active administrator") from exc
    if not deleted:
        raise HTTPException(status_code=404, detail="User not found")
    await asyncio.to_thread(sessions.revoke_for_user, user_id)
    return DeleteUserResponse(deleted=True)
