from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
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
from app.schemas import LoginIn, RegisterIn, UserOut

router = APIRouter(prefix="/auth", tags=["auth"])


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        max_age=settings.session_ttl_hours * 3600,
        httponly=True,
        samesite="lax",
        # Not `secure=True`: this app runs over plain http://localhost in dev, and a secure
        # cookie is silently dropped by the browser on a non-https origin -- which would make
        # login look like it "does nothing." Revisit if this is ever deployed over https.
        secure=False,
        path="/",
    )


@router.post("/login", response_model=UserOut)
def login(payload: LoginIn, response: Response, db: Session = Depends(get_db)) -> UserOut:
    user = db.execute(select(User).where(User.email == payload.email.lower())).scalar_one_or_none()
    if user is None or not verify_password(payload.password, user.password_hash):
        # Identical message for "no such user" and "wrong password" -- distinguishing them
        # would let an attacker enumerate which emails have accounts.
        raise HTTPException(status_code=401, detail="Incorrect email or password.")

    session = create_session(db, user)
    _set_session_cookie(response, session.token)
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
    response.delete_cookie(key=settings.session_cookie_name, path="/")
    return {"status": "signed_out"}


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> UserOut:
    return UserOut.model_validate(user)


@router.get("/roles")
def list_roles() -> list[str]:
    """The fixed set of roles an admin can assign when creating a user -- not user-editable."""
    return list(ALL_ROLES)


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(
    payload: RegisterIn,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role(*CAN_MANAGE_USERS)),
) -> UserOut:
    """Administrator-only: create a new account. There is no public self-registration endpoint --
    a real access-controlled system doesn't let a visitor grant themselves a role."""
    if payload.role not in ALL_ROLES:
        raise HTTPException(status_code=422, detail=f"role must be one of: {', '.join(ALL_ROLES)}")

    email = payload.email.lower()
    existing = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status_code=409, detail="An account with this email already exists.")

    user = User(name=payload.name, email=email, password_hash=hash_password(payload.password), role=payload.role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return UserOut.model_validate(user)


@router.get("/users", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), _admin: User = Depends(require_role(*CAN_MANAGE_USERS))) -> list[UserOut]:
    rows = db.execute(select(User).order_by(User.created_at)).scalars().all()
    return [UserOut.model_validate(row) for row in rows]
