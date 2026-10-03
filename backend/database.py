# backend/database.py
"""Database connection utilities for SystemX.
We support PostgreSQL in production (via environment variable DATABASE_URL)
and SQLite for quick local development.
"""
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

# Example: postgresql://user:password@db:5432/systemx
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./systemx.db")

engine = create_engine(
    DATABASE_URL,
    connect_args=(
        {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
    ),
    pool_pre_ping=True,
)

SessionLocal = scoped_session(
    sessionmaker(autocommit=False, autoflush=False, bind=engine)
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
