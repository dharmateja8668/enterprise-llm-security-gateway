import os
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import fakeredis
import respx
import httpx

from app.main import app
from app.db import Base, get_db
import app.security.rate_limiter as rate_limiter_module
from app.routes.basic_chat import _reset_ollama

# Create a clean in-memory SQLite database for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, 
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

@pytest.fixture(autouse=True)
def setup_test_environment():
    """Apply dependency overrides, create tables, and set up mock env vars."""
    app.dependency_overrides[get_db] = override_get_db
    
    # Create the tables in the test database
    Base.metadata.create_all(bind=engine)
    
    # Mock environment variables and reset state
    os.environ["GATEWAY_API_KEY"] = "test-token"
    os.environ["OLLAMA_BASE_URL"] = "http://localhost:11434"
    os.environ["OLLAMA_MODEL"] = "tinyllama"
    fake = fakeredis.FakeRedis(decode_responses=True)
    rate_limiter_module.set_redis_client(fake)
    _reset_ollama()
    
    yield
    
    # Clean up
    Base.metadata.drop_all(bind=engine)
    app.dependency_overrides.clear()
    for key in ["GATEWAY_API_KEY", "OLLAMA_BASE_URL", "OLLAMA_MODEL"]:
        os.environ.pop(key, None)
    rate_limiter_module.reset_redis_client()
