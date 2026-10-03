from sqlalchemy import Column, Integer, String
from app.db import Base

class RBACPolicy(Base):
    __tablename__ = "rbac_policies"

    id = Column(Integer, primary_key=True, index=True)
    department = Column(String(100), nullable=False)
    role = Column(String(50), nullable=False)
    allowed_model = Column(String(100), nullable=False)
