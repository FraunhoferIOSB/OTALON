"""Product login, session lifecycle, and password-change endpoints."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from otalon_api.api.schemas.auth import (
    ChangePasswordRequest,
    CurrentUserResponse,
    LoginRequest,
    LoginResponse,
    LogoutResponse,
)
from otalon_api.dependencies import get_session_repo, get_settings, get_user_repo
from otalon_api.middleware.session_auth import SESSION_COOKIE_NAME, require_session
from otalon_api.repositories.identity_repo import SessionRepository, UserEntry, UserRepository
from otalon_api.settings import Settings

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


def _secure_cookie(request: Request, settings: Settings) -> bool:
    """Return whether request arrived over HTTPS, respecting the TLS proxy."""
    forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip()
    scheme = forwarded_proto or request.url.scheme
    return settings.session_cookie_secure and scheme.lower() == "https"


def _set_session_cookie(request: Request, response: Response, session_id: str, settings: Settings) -> None:
    """Set production session cookie flags without exposing session value in body."""
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_id,
        httponly=True,
        secure=_secure_cookie(request, settings),
        samesite="lax",
        path="/",
    )


def _clear_session_cookie(request: Request, response: Response, settings: Settings) -> None:
    """Clear session cookie using same production attributes."""
    response.delete_cookie(
        SESSION_COOKIE_NAME,
        secure=_secure_cookie(request, settings),
        httponly=True,
        samesite="lax",
        path="/",
    )


@router.post("/login", response_model=LoginResponse)
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    users: UserRepository = Depends(get_user_repo),
    sessions: SessionRepository = Depends(get_session_repo),
    settings: Settings = Depends(get_settings),
) -> LoginResponse:
    """Verify credentials and establish an opaque server-side session."""
    user = await asyncio.to_thread(users.authenticate, body.username, body.password)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    session_id = await asyncio.to_thread(
        sessions.create,
        user.id,
        request.client.host if request.client else None,
        request.headers.get("user-agent"),
    )
    await asyncio.to_thread(users.mark_login, user.id)
    _set_session_cookie(request, response, session_id, settings)
    return LoginResponse(
        username=user.username,
        role=user.role,
        must_change_password=user.must_change_password,
    )


@router.post("/logout", response_model=LogoutResponse)
async def logout(
    request: Request,
    response: Response,
    user: UserEntry = Depends(require_session),
    sessions: SessionRepository = Depends(get_session_repo),
    settings: Settings = Depends(get_settings),
) -> LogoutResponse:
    """Revoke current session and clear its browser cookie."""
    del user
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if session_id:
        await asyncio.to_thread(sessions.revoke, session_id)
    _clear_session_cookie(request, response, settings)
    return LogoutResponse(status="logged_out")


@router.get("/me", response_model=CurrentUserResponse)
async def me(user: UserEntry = Depends(require_session)) -> CurrentUserResponse:
    """Return current authenticated product identity and role."""
    return CurrentUserResponse(
        id=user.id,
        username=user.username,
        role=user.role,
        must_change_password=user.must_change_password,
    )


@router.post("/change-password", response_model=CurrentUserResponse)
async def change_password(
    body: ChangePasswordRequest,
    user: UserEntry = Depends(require_session),
    users: UserRepository = Depends(get_user_repo),
) -> CurrentUserResponse:
    """Store new Argon2id password and clear forced-change state."""
    await asyncio.to_thread(users.update_password, user.id, body.new_password)
    return CurrentUserResponse(
        id=user.id,
        username=user.username,
        role=user.role,
        must_change_password=False,
    )
