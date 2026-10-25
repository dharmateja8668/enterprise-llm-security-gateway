from sqlalchemy import Column, String, Integer, Text, DateTime, func
from app.db import Base

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    request_id = Column(String, index=True, nullable=False)
    user_id = Column(String, nullable=True)
    provider = Column(String, nullable=False)
    model = Column(String, nullable=False)
    prompt = Column(Text, nullable=False)  # raw JSON of messages
    response = Column(Text, nullable=True)
    status = Column(String, nullable=False)  # "success" or "error"
    status_code = Column(Integer, nullable=True) # HTTP status code
    error_message = Column(Text, nullable=True)
    latency_ms = Column(Integer, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
