"""
app/routes/rbac.py
Endpoints for managing Role-Based Access Control (RBAC) policies and user roles.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session
from app.db import get_db
from app.models.rbac import RBACPolicy
from app.models.user import User
from app.security.rbac import init_default_rbac_policies

router = APIRouter(prefix="/rbac", tags=["RBAC"])


class PolicyCreate(BaseModel):
    department: str
    role: str
    allowed_model: str


class PolicyResponse(BaseModel):
    id: int
    department: str
    role: str
    allowed_model: str

    model_config = ConfigDict(from_attributes=True)


class UserRoleUpdate(BaseModel):
    department: Optional[str] = None
    role: Optional[str] = None


@router.get("/policies", response_model=List[PolicyResponse])
def list_policies(db: Session = Depends(get_db)):
    """List all configured RBAC policies."""
    return db.query(RBACPolicy).all()


@router.post("/policies", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
def create_policy(policy_data: PolicyCreate, db: Session = Depends(get_db)):
    """Create a new RBAC policy."""
    policy = RBACPolicy(
        department=policy_data.department,
        role=policy_data.role,
        allowed_model=policy_data.allowed_model,
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)
    return policy


@router.delete("/policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_policy(policy_id: int, db: Session = Depends(get_db)):
    """Delete an RBAC policy by ID."""
    policy = db.query(RBACPolicy).filter(RBACPolicy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    db.delete(policy)
    db.commit()
    return None


@router.post("/seed")
def seed_policies(db: Session = Depends(get_db)):
    """Seed default RBAC policies if none exist."""
    init_default_rbac_policies(db)
    return {"message": "Default RBAC policies seeded successfully"}


@router.patch("/users/{username}")
def update_user_role(username: str, data: UserRoleUpdate, db: Session = Depends(get_db)):
    """Update a user's department and role."""
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail=f"User '{username}' not found")
    if data.department is not None:
        user.department = data.department
    if data.role is not None:
        user.role = data.role
    db.commit()
    db.refresh(user)
    return {
        "username": user.username,
        "department": user.department,
        "role": user.role,
    }
