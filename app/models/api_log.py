from sqlalchemy import Column, Integer, String, Float, Text, DateTime, ForeignKey, func
from sqlalchemy.orm import relationship
from app.db import Base

class APILog(Base):
    __tablename__ = "api_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    request_id = Column(String(100), unique=True, nullable=False)
    endpoint = Column(String(255), nullable=False)
    method = Column(String(10), nullable=False)
    status_code = Column(Integer)
    response_time_ms = Column(Float)
    ip_address = Column(String(45))
    model_name = Column(String(100))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # relationship back to User
    user = relationship("User", back_populates="api_logs")
