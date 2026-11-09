"""Pydantic contracts for product authentication endpoints."""

from __future__ import annotations

from otalon_common.auth import UserRole
from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    """Credentials submitted to product login."""

    username: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=1, max_length=1024)


class ChangePasswordRequest(BaseModel):
    """New password submitted during self-service password change."""

    new_password: str = Field(min_length=12, max_length=1024)


class CurrentUserResponse(BaseModel):
    """Safe current-user identity response without credential material."""

    id: int
    username: str
    role: UserRole
    must_change_password: bool


class LoginResponse(BaseModel):
    """Safe successful login response without session credentials."""

    username: str
    role: UserRole
    must_change_password: bool


class LogoutResponse(BaseModel):
    """Successful logout response."""

    status: str
