from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import Role, hash_password
from app.models import User

logger = logging.getLogger("netshield.backend")

# One demo account per role, so real login actually has something to sign in with on a fresh
# database -- otherwise turning on real authentication would lock everyone out with no way in.
# Same default password for all four; this is a local dev/demo seed, not a production user store.
_DEFAULT_PASSWORD = "NetShield@123"
_DEFAULT_ACCOUNTS = [
    ("Ava Administrator", "admin@netshield.ai", Role.ADMINISTRATOR),
    ("Sam Analyst", "analyst@netshield.ai", Role.SECURITY_ANALYST),
    ("Hank Hunter", "hunter@netshield.ai", Role.THREAT_HUNTER),
    ("Val Viewer", "viewer@netshield.ai", Role.VIEWER),
]


def ensure_default_users(db: Session) -> None:
    """Creates the four demo accounts above only if the users table is completely empty --
    never touches it again after that, so it won't stomp on real accounts an admin creates
    or edits later."""
    existing_count = db.execute(select(User.id)).first()
    if existing_count is not None:
        return

    for name, email, role in _DEFAULT_ACCOUNTS:
        db.add(User(name=name, email=email, password_hash=hash_password(_DEFAULT_PASSWORD), role=role))
    db.commit()

    logger.info(
        "No users existed yet -- seeded 4 demo accounts (all with password '%s'): %s",
        _DEFAULT_PASSWORD,
        ", ".join(email for _, email, _ in _DEFAULT_ACCOUNTS),
    )
