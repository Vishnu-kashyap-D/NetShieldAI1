from __future__ import annotations

import functools
import math

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth import (
    ALL_ROLES,
    CAN_MANAGE_USERS,
    create_session,
    get_current_user,
    hash_password,
    invalidate_session,
    require_role,
    verify_password,
)
from app.config import settings
from app.database import get_db
from app.models import User
from app.ratelimit import SlidingWindowLimiter
from app.schemas import LoginIn, RegisterIn, SignupIn, UserOut

router = APIRouter(prefix="/auth", tags=["auth"])

# Failed-login throttling. Two independent limits, both must be clear to even attempt a password:
#   - per (client IP, email): stops guessing one account's password from one address, but does NOT
#     let an attacker lock the real owner out from a different address (the key includes the IP);
#   - per client IP: stops one address spraying guesses across many different emails.
# Only *failed* attempts count, and a blocked attempt records nothing (so retrying while locked
# out doesn't extend the lockout). A successful login clears that account's counter.
_login_account_limiter = SlidingWindowLimiter(settings.login_max_failures, settings.login_window_seconds)
_login_ip_limiter = SlidingWindowLimiter(settings.login_ip_max_failures, settings.login_window_seconds)
# Self-registration throttle: every attempt counts (not just failures), per client IP. See the
# allow_self_registration comment in config.py for why this matters beyond spam.
_register_ip_limiter = SlidingWindowLimiter(settings.register_ip_max_attempts, settings.register_window_seconds)

_DUPLICATE_EMAIL_DETAIL = "An account with this email already exists."


@functools.lru_cache(maxsize=1)
def _timing_decoy_hash() -> str:
    """A real bcrypt hash of a throwaway password, made once with the same cost as every real account's.

    A login for an email with no account used to skip the (deliberately slow) password check and answer in
    milliseconds, while a wrong password on a real account took ~0.25 s -- so response time alone revealed which
    emails have accounts, defeating the identical error message. Checking against this decoy makes both paths
    take the same time."""
    return hash_password("this-account-does-not-exist")


def _client_ip(request: Request) -> str:
    # The direct socket peer, not X-Forwarded-For: any client can send that header with any value,
    # so trusting it would let an attacker dodge the limit by rotating a fake address.
    return request.client.host if request.client else "unknown"


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        max_age=settings.session_ttl_hours * 3600,
        httponly=True,
        samesite="lax",
        # See Settings.session_cookie_secure: False only because local dev is plain http.
        secure=settings.session_cookie_secure,
        path="/",
    )


@router.post("/login", response_model=UserOut)
def login(payload: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)) -> UserOut:
    ip = _client_ip(request)
    account_key = f"{ip}|{payload.email.lower()}"

    wait = max(_login_account_limiter.retry_after(account_key), _login_ip_limiter.retry_after(ip))
    if wait > 0:
        seconds = math.ceil(wait)
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed sign-in attempts. Try again in {seconds} second{'s' if seconds != 1 else ''}.",
            headers={"Retry-After": str(seconds)},
        )

    user = db.execute(select(User).where(User.email == payload.email.lower())).scalar_one_or_none()
    # Always run exactly one password check, whether or not the account exists (see _timing_decoy_hash).
    password_ok = verify_password(payload.password, user.password_hash if user is not None else _timing_decoy_hash())
    if user is None or not password_ok:
        _login_account_limiter.record(account_key)
        _login_ip_limiter.record(ip)
        # Identical message for "no such user" and "wrong password" -- distinguishing them
        # would let an attacker enumerate which emails have accounts.
        raise HTTPException(status_code=401, detail="Incorrect email or password.")

    _login_account_limiter.clear(account_key)
    _, raw_token = create_session(db, user)
    _set_session_cookie(response, raw_token)
    return UserOut.model_validate(user)


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    _user: User = Depends(get_current_user),  # 401s here if there's no valid session to log out of
    db: Session = Depends(get_db),
) -> dict:
    # Deletes only this one session row (this browser's), not every session belonging to the
    # user -- signing out on one device shouldn't sign the user out everywhere.
    token = request.cookies.get(settings.session_cookie_name)
    if token:
        invalidate_session(db, token)
    response.delete_cookie(
        key=settings.session_cookie_name,
        path="/",
        secure=settings.session_cookie_secure,
        httponly=True,
        samesite="lax",
    )
    return {"status": "signed_out"}


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> UserOut:
    return UserOut.model_validate(user)


@router.get("/roles")
def list_roles(_user: User = Depends(get_current_user)) -> list[str]:
    """The fixed set of roles an admin can assign when creating a user -- not user-editable.

    Needs a session like every route except /health (it used to be open, which contradicted that rule)."""
    return list(ALL_ROLES)


def _insert_user(db: Session, *, name: str, email: str, password: str, role: str) -> User:
    """Creates the account, or 409s if the email is taken.

    The up-front lookup gives the normal case a clean error; the IntegrityError catch covers two
    requests for the same email racing past that lookup at once -- the unique index on users.email
    lets only one insert win, and the loser gets the same 409 instead of a 500."""
    if db.execute(select(User).where(User.email == email)).scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail=_DUPLICATE_EMAIL_DETAIL)
    user = User(name=name, email=email, password_hash=hash_password(password), role=role)
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail=_DUPLICATE_EMAIL_DETAIL) from None
    db.refresh(user)
    return user


@router.post("/register", response_model=UserOut, status_code=201)
def register(payload: SignupIn, request: Request, response: Response, db: Session = Depends(get_db)) -> UserOut:
    """Public self-registration. Always creates a **Viewer** (the payload has no role field), then signs
    the new user in by setting the session cookie, the same way /login does.

    Throttled per client IP on every attempt, successful or not: a duplicate email has to be refused, so
    unlike /login this endpoint can't hide whether an email has an account -- the throttle is what stops it
    being used to check thousands of emails quickly. Disabled entirely with ALLOW_SELF_REGISTRATION=false."""
    if not settings.allow_self_registration:
        raise HTTPException(
            status_code=403,
            detail="Self-registration is turned off on this server. Ask an Administrator for an account.",
        )

    wait = _register_ip_limiter.acquire(_client_ip(request))
    if wait > 0:
        seconds = math.ceil(wait)
        minutes = math.ceil(seconds / 60)
        raise HTTPException(
            status_code=429,
            detail=f"Too many sign-up attempts from this address. Try again in {minutes} minute{'s' if minutes != 1 else ''}.",
            headers={"Retry-After": str(seconds)},
        )

    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Name must not be blank.")

    user = _insert_user(db, name=name, email=payload.email.lower(), password=payload.password, role="Viewer")
    _, raw_token = create_session(db, user)
    _set_session_cookie(response, raw_token)
    return UserOut.model_validate(user)


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(
    payload: RegisterIn,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role(*CAN_MANAGE_USERS)),
) -> UserOut:
    """Administrator-only: create an account with any role. The only way to get a role above Viewer --
    public sign-up (/register) always creates Viewers, so a visitor can never grant themselves a role."""
    if payload.role not in ALL_ROLES:
        raise HTTPException(status_code=422, detail=f"role must be one of: {', '.join(ALL_ROLES)}")
    user = _insert_user(db, name=payload.name, email=payload.email.lower(), password=payload.password, role=payload.role)
    return UserOut.model_validate(user)


@router.get("/users", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), _admin: User = Depends(require_role(*CAN_MANAGE_USERS))) -> list[UserOut]:
    rows = db.execute(select(User).order_by(User.created_at)).scalars().all()
    return [UserOut.model_validate(row) for row in rows]
