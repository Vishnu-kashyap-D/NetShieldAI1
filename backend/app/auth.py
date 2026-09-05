from __future__ import annotations

import datetime as dt
import secrets

import bcrypt
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session as DbSession

from app.config import settings
from app.database import get_db
from app.models import User, UserSession


class Role:
    """The four roles the frontend's login screen has always shown -- now actually enforced.

    A role is a fact about a user's account (set at creation), never something a client
    self-selects at login time. These strings must match exactly what the frontend renders.
    """

    VIEWER = "Viewer"
    SECURITY_ANALYST = "Security Analyst"
    THREAT_HUNTER = "Threat Hunter"
    ADMINISTRATOR = "Administrator"


ALL_ROLES = (Role.VIEWER, Role.SECURITY_ANALYST, Role.THREAT_HUNTER, Role.ADMINISTRATOR)

# Permission matrix. Every authenticated role (including Viewer) can read alerts/stats/analytics
# and use both chatbots -- there's no "can read" set below because that's just "any logged-in
# user" (see get_current_user). Only the state-changing actions below are role-gated.
CAN_SUBMIT_FEEDBACK = {Role.SECURITY_ANALYST, Role.THREAT_HUNTER, Role.ADMINISTRATOR}
CAN_INGEST_TRAFFIC = {Role.THREAT_HUNTER, Role.ADMINISTRATOR}
CAN_TRIGGER_RETRAIN = {Role.ADMINISTRATOR}
CAN_MANAGE_USERS = {Role.ADMINISTRATOR}


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def verify_password(plain: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), password_hash.encode("ascii"))
    except ValueError:
        # Malformed hash (shouldn't happen for rows this app wrote) -- fail closed, not open.
        return False


def create_session(db: DbSession, user: User) -> UserSession:
    session = UserSession(
        token=secrets.token_urlsafe(48),
        user_id=user.id,
        expires_at=dt.datetime.utcnow() + dt.timedelta(hours=settings.session_ttl_hours),
    )
    db.add(session)
    db.commit()
    return session


def invalidate_session(db: DbSession, token: str) -> None:
    session = db.get(UserSession, token)
    if session is not None:
        db.delete(session)
        db.commit()


def get_current_user(request: Request, db: DbSession = Depends(get_db)) -> User:
    """FastAPI dependency: resolves the session cookie to a User, or raises 401.

    Reads the cookie via `Request` directly (rather than a `Cookie(...)` parameter) so the
    cookie name stays driven by `settings.session_cookie_name` in one place instead of being
    hardcoded into every route signature that needs auth.
    """
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated.")

    session = db.get(UserSession, token)
    if session is None:
        raise HTTPException(status_code=401, detail="Session not found or already logged out.")
    if session.expires_at < dt.datetime.utcnow():
        db.delete(session)
        db.commit()
        raise HTTPException(status_code=401, detail="Session expired. Please sign in again.")

    user = db.get(User, session.user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="Account no longer exists.")
    return user


def require_role(*allowed_roles: str):
    """FastAPI dependency factory: authenticates the request, then enforces role membership.

    Usage: `user: User = Depends(require_role(*CAN_TRIGGER_RETRAIN))`. Always authenticates
    first (401 for no/invalid session) before ever checking role (403 for wrong role), so a
    logged-out request never learns anything about what roles a route requires.
    """

    def dependency(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"This action requires one of these roles: {', '.join(allowed_roles)}. Your role is {user.role}.",
            )
        return user

    return dependency
