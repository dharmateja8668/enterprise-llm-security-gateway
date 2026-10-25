from logging.config import fileConfig
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy import pool
from alembic import context

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

import os
from dotenv import load_dotenv

# Load .env from the project root (one level above alembic/)
_project_root = Path(__file__).resolve().parent.parent
load_dotenv(dotenv_path=_project_root / ".env")

from app.db import Base  # noqa: E402
from app.models import User, APILog, SecurityLog, AuditLog, RequestLog, RBACPolicy  # noqa: E402

target_metadata = Base.metadata


def _get_url() -> str:
    url = os.getenv("POSTGRES_URL") or os.getenv("DATABASE_URL")
    if url:
        return url
    user = os.getenv("POSTGRES_USER")
    password = os.getenv("POSTGRES_PASSWORD")
    host = os.getenv("POSTGRES_HOST", "127.0.0.1")
    port = os.getenv("POSTGRES_PORT", "5432")
    db = os.getenv("POSTGRES_DB", "gateway")
    if user and password:
        return f"postgresql+psycopg2://{user}:{password}@{host}:{port}/{db}"
    return "sqlite:///./gateway.db"


def run_migrations_offline() -> None:
    url = _get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    url = _get_url()
    connectable = create_engine(url, poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
