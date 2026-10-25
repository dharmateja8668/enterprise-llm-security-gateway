"""
app/routes/auth.py
User Authentication & Session Management Endpoints.

Provides login, logout, profile inspection, and user RBAC verification.
"""

import hashlib
import logging
import os
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.log import RequestLog
from app.models.rbac import RBACPolicy
from app.models.user import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])


import hmac
import secrets


def hash_password(password: str) -> str:
    """Return salted PBKDF2-HMAC-SHA256 hash formatted as pbkdf2:sha256:100000$<salt>$<hex_hash>."""
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
    return f"pbkdf2:sha256:100000${salt}${dk.hex()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify password using constant-time comparison against salted PBKDF2 or legacy SHA-256 digest.
    Strictly rejects plaintext passwords.
    """
    if not plain_password or not hashed_password:
        return False

    # Modern salted PBKDF2 format
    if hashed_password.startswith("pbkdf2:sha256:"):
        parts = hashed_password.split("$")
        if len(parts) == 3:
            _, salt, expected_hex = parts
            dk = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt.encode("utf-8"), 100_000)
            return hmac.compare_digest(dk.hex(), expected_hex)

    # Legacy SHA-256 hex digest (64 chars) support with constant-time comparison
    if len(hashed_password) == 64 and all(c in "0123456789abcdefABCDEF" for c in hashed_password):
        candidate_hex = hashlib.sha256(plain_password.encode("utf-8")).hexdigest()
        return hmac.compare_digest(candidate_hex, hashed_password)

    # Reject any plaintext or unrecognized format
    return False


ALLOWED_ORGANIZATION_DOMAIN = "zaalima.in"


def validate_zaalima_email_domain(email_or_identifier: str) -> bool:
    """
    Validates that an email address belongs strictly to the '@zaalima.in' domain.
    Converts domain check to lowercase and enforces exact domain matching.

    Examples:
        employee@zaalima.in             -> True
        Employee@ZAALIMA.IN             -> True
        employee@gmail.com              -> False
        employee@zaalima.com            -> False
        employee@zaalima.in.example.com -> False
        employee@examplezaalima.in      -> False
    """
    if not email_or_identifier or not isinstance(email_or_identifier, str):
        return False

    clean_str = email_or_identifier.strip().lower()

    if "@" in clean_str:
        parts = clean_str.split("@")
        if len(parts) != 2:
            return False
        local_part, domain_part = parts[0].strip(), parts[1].strip()
        if not local_part or domain_part != ALLOWED_ORGANIZATION_DOMAIN:
            return False
        return True

    return False


class LoginRequest(BaseModel):
    username_or_email: Optional[str] = None
    username: Optional[str] = None
    email: Optional[str] = None
    password: str


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    department: Optional[str] = "Engineering"
    role: Optional[str] = "employee"


class UserProfileResponse(BaseModel):
    id: int
    username: str
    email: str
    department: Optional[str] = None
    role: Optional[str] = "employee"
    is_active: bool

    model_config = ConfigDict(from_attributes=True)


class LoginSuccessResponse(BaseModel):
    success: bool
    access_token: str
    token_type: str = "bearer"
    user: UserProfileResponse
    allowed_models: List[str]


@router.post("/login", response_model=LoginSuccessResponse)
def login(data: LoginRequest, db: Session = Depends(get_db)):
    """
    Authenticate user using email/username and password.
    Enforces strict @zaalima.in organizational email domain verification.
    """
    identifier = (data.username_or_email or data.username or data.email or "").strip()
    if not identifier:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email is required",
        )

    # 1. Lookup user (case-insensitive for username and email)
    clean_identifier = identifier.strip().lower()
    user = (
        db.query(User)
        .filter(
            (func.lower(User.username) == clean_identifier)
            | (func.lower(User.email) == clean_identifier)
        )
        .first()
    )

    # 2. Strict @zaalima.in Domain Enforcement (BEFORE token creation)
    target_email = user.email if user else identifier
    if not validate_zaalima_email_domain(target_email):
        logger.warning("Rejected login attempt for non-@zaalima.in domain: %s", target_email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Only @zaalima.in organizational accounts are allowed.",
        )

    if not user:
        logger.warning("Failed login attempt for unknown user: %s", identifier)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials or account disabled",
        )

    if not user.is_active:
        logger.warning("Login attempt for disabled user: %s", user.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is disabled",
        )

    # 2. Verify password
    if not verify_password(data.password, user.password_hash):
        logger.warning("Failed login attempt (bad password) for user: %s", user.username)
        try:
            import uuid
            db.add(
                RequestLog(
                    request_id=str(uuid.uuid4()),
                    user_token=user.username,
                    provider="gateway_auth",
                    model="none",
                    prompt="[LOGIN_FAILED]",
                    status="error",
                )
            )
            db.commit()
        except Exception as err:
            logger.error("Failed to write audit log: %s", err)
            db.rollback()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # 3. Log successful login audit record
    try:
        import uuid
        db.add(
            RequestLog(
                request_id=str(uuid.uuid4()),
                user_token=user.username,
                provider="gateway_auth",
                model="none",
                prompt="[LOGIN_SUCCESS]",
                status="success",
            )
        )
        db.commit()
    except Exception as err:
        logger.error("Failed to write audit log: %s", err)
        db.rollback()

    # 4. Fetch allowed models for user's department & role
    user_role = (user.role or "employee").lower()
    user_dept = (user.department or "").lower()

    default_configured_model = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
    all_known_models = list(set([default_configured_model, "llama3.2:3b", "tinyllama"]))

    if user_role == "admin":
        allowed_models = all_known_models
    else:
        # Filter models from RBAC Policies table
        policies = db.query(RBACPolicy).all()
        allowed = set()
        for p in policies:
            dept_match = p.department.lower() in ["*", "any"] or (user_dept and p.department.lower() == user_dept)
            role_match = p.role.lower() in ["*", "any"] or (user_role and p.role.lower() == user_role)
            if dept_match and role_match:
                if p.allowed_model.lower() in ["*", "any"]:
                    allowed.update(all_known_models)
                else:
                    allowed.add(p.allowed_model)

        if not allowed:
            # Fallback to configured model if no policy specified
            allowed = set([default_configured_model])

        allowed_models = sorted(list(allowed))

    token = os.getenv("GATEWAY_API_KEY", "dev-gateway-key-llama3")

    return LoginSuccessResponse(
        success=True,
        access_token=token,
        user=UserProfileResponse.model_validate(user),
        allowed_models=allowed_models,
    )


@router.post("/register", response_model=UserProfileResponse)
def register(data: RegisterRequest, db: Session = Depends(get_db)):
    """
    Register a new user account.
    Enforces strict @zaalima.in organizational email domain verification.
    """
    clean_email = data.email.strip().lower()
    if not validate_zaalima_email_domain(clean_email):
        logger.warning("Rejected registration attempt for non-@zaalima.in domain: %s", clean_email)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only @zaalima.in organizational accounts are allowed.",
        )

    existing = db.query(User).filter((User.username == data.username) | (User.email == clean_email)).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered.",
        )

    new_user = User(
        username=data.username,
        email=clean_email,
        password_hash=hash_password(data.password),
        department=data.department or "Engineering",
        role=data.role or "employee",
        is_active=True,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return UserProfileResponse.model_validate(new_user)


@router.post("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    """Record user logout audit log."""
    auth_header = request.headers.get("Authorization", "")
    try:
        import uuid
        db.add(
            RequestLog(
                request_id=str(uuid.uuid4()),
                user_token=auth_header[:16] if auth_header else "unknown",
                provider="gateway_auth",
                model="none",
                prompt="[LOGOUT]",
                status="success",
            )
        )
        db.commit()
    except Exception as err:
        logger.error("Failed to write logout audit log: %s", err)
        db.rollback()

    return {"success": True, "message": "Logged out successfully"}


@router.get("/me", response_model=UserProfileResponse)
def get_current_user_profile(user_id: str, db: Session = Depends(get_db)):
    """Fetch profile of current user by username, email, or numeric ID."""
    user = None
    if str(user_id).isdigit():
        user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        user = db.query(User).filter(User.username == user_id).first()
    if not user:
        user = db.query(User).filter(User.email == user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{user_id}' not found",
        )

    return UserProfileResponse.model_validate(user)
