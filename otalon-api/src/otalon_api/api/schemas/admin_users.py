"""Pydantic contracts for administrator user management."""

from __future__ import annotations

from datetime import datetime

from otalon_common.auth import UserRole
from pydantic import BaseModel, Field


class UserCreateRequest(BaseModel):
    """Administrator request for creating a forced-change user."""

    username: str = Field(min_length=1, max_length=120)
    role: UserRole


class UserPatchRequest(BaseModel):
    """Optional administrator updates to role and disabled state."""

    role: UserRole | None = None
    disabled: bool | None = None


class UserResponse(BaseModel):
    """Safe user representation without password material."""

    id: int
    username: str
    role: UserRole
    disabled: bool
    must_change_password: bool
    created_at: datetime | None
    last_login_at: datetime | None


class UserListResponse(BaseModel):
    """Administrator user-list response."""

    users: list[UserResponse]


class OneTimePasswordResponse(BaseModel):
    """Response carrying a generated password exactly once."""

    user: UserResponse
    one_time_password: str


class DeleteUserResponse(BaseModel):
    """Successful user deletion response."""

    deleted: bool
