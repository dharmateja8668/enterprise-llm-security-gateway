"""
app/security/rbac.py
Role-Based Access Control (RBAC) Security Enforcement Module.

Hierarchy:
  User -> Department -> Role -> Allowed AI Model

Policy evaluation:
  1. If role is 'admin', access is granted for any model.
  2. If user exists in DB, query rbac_policies table for matching
     (department, role, allowed_model) allowing wildcard ('*', 'Any').
  3. If user is not found in DB (e.g. standard API key request), allow
     default access to maintain backward compatibility with legacy calls.
"""

import os
import logging
from typing import Optional
from sqlalchemy.orm import Session
from app.models.user import User
from app.models.rbac import RBACPolicy

logger = logging.getLogger(__name__)


def check_rbac_access(
    db: Session,
    user_identifier: Optional[str],
    target_model: str,
) -> bool:
    """
    Evaluates whether a user is authorized to access the specified target AI model.

    Args:
        db: SQLAlchemy database session.
        user_identifier: Username, email, or user ID.
        target_model: Name of the AI model being requested (e.g. "llama3.2:3b").

    Returns:
        True if access is allowed, False if access is denied.
    """
    if not user_identifier:
        return True

    # 1. Lookup user in database
    user = None
    if str(user_identifier).isdigit():
        user = db.query(User).filter(User.id == int(user_identifier)).first()
    if not user:
        user = db.query(User).filter(User.username == user_identifier).first()
    if not user:
        user = db.query(User).filter(User.email == user_identifier).first()

    # If user not registered in DB, default access allowed (legacy API key caller)
    if not user:
        return True

    # 2. Admin role check
    role = (user.role or "employee").strip()
    if role.lower() == "admin":
        return True

    department = (user.department or "").strip()
    target_model_clean = (target_model or "").strip()

    # 3. Query RBAC Policies
    policies = db.query(RBACPolicy).all()

    for policy in policies:
        dept_match = (
            policy.department.lower() in ["*", "any"]
            or (department and policy.department.lower() == department.lower())
        )
        role_match = (
            policy.role.lower() in ["*", "any"]
            or (role and policy.role.lower() == role.lower())
        )
        model_match = (
            policy.allowed_model.lower() in ["*", "any"]
            or policy.allowed_model.lower() == target_model_clean.lower()
        )

        if dept_match and role_match and model_match:
            return True

    return False


def init_default_rbac_policies(db: Session):
    """Seed default RBAC policies and test accounts if empty."""
    configured_model = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
    default_models = set([configured_model, "llama3.2:3b", "tinyllama"])

    # 1. Seed Policies
    existing_policy_count = db.query(RBACPolicy).count()
    if existing_policy_count == 0:
        for model in default_models:
            db.add(RBACPolicy(department="Engineering", role="employee", allowed_model=model))
            db.add(RBACPolicy(department="Cybersecurity", role="employee", allowed_model=model))
            db.add(RBACPolicy(department="Security", role="employee", allowed_model=model))
            db.add(RBACPolicy(department="Security", role="security_analyst", allowed_model=model))
            db.add(RBACPolicy(department="HR", role="employee", allowed_model="tinyllama"))
        db.commit()

    # 2. Seed Default Accounts with @zaalima.in organizational domain
    import hashlib
    def h(p: str) -> str:
        return hashlib.sha256(p.encode("utf-8")).hexdigest()

    default_users_data = [
        ("employee_user", "employee@zaalima.in", "Employee@123", "Engineering", "employee"),
        ("finance_user", "finance@zaalima.in", "Finance@123", "Finance", "employee"),
        ("analyst_user", "analyst@zaalima.in", "Analyst@123", "Security", "security_analyst"),
        ("admin_user", "admin@zaalima.in", "Admin@123", "Security", "admin"),
    ]

    # Migrate any legacy non-zaalima.in accounts to @zaalima.in domain
    existing_users = db.query(User).all()
    for u in existing_users:
        if u.email and not u.email.strip().lower().endswith("@zaalima.in"):
            local_part = u.email.split("@")[0] if "@" in u.email else u.username
            u.email = f"{local_part}@zaalima.in"

    for uname, email, plain_pass, dept, role in default_users_data:
        u = db.query(User).filter((User.username == uname) | (User.email == email)).first()
        if not u:
            db.add(User(
                username=uname,
                email=email,
                password_hash=h(plain_pass),
                department=dept,
                role=role,
                is_active=True,
            ))
        else:
            u.email = email
            u.password_hash = h(plain_pass)
            u.department = dept
            u.role = role
            u.is_active = True
    db.commit()

