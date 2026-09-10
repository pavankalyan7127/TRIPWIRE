"""SQLAlchemy engine and session management."""

from collections.abc import Generator
from typing import Optional

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import settings
from app.db.base import Base

# Global engine instance (singleton pattern for the application)
_engine: Optional[object] = None
_session_factory: Optional[sessionmaker] = None


def get_engine():
    """Get or create the SQLAlchemy engine.

    Returns the singleton engine instance for the configured database URL.
    """
    global _engine
    if _engine is None:
        _engine = create_engine(
            settings.database_url,
            echo=False,  # Set to True for SQL query logging during development
            connect_args={"check_same_thread": False} if settings.database_url.startswith("sqlite") else {},
        )
    return _engine


def get_session_factory() -> sessionmaker:
    """Get or create the SQLAlchemy session factory.

    Returns a sessionmaker bound to the application engine.
    """
    global _session_factory
    if _session_factory is None:
        engine = get_engine()
        _session_factory = sessionmaker(
            bind=engine,
            autocommit=False,
            autoflush=False,
            expire_on_commit=False,
        )
    return _session_factory


def get_db() -> Generator[Session, None, None]:
    """Dependency function to get a database session.

    Yields a SQLAlchemy session and ensures it is closed after use.
    Intended for FastAPI dependency injection in later phases.

    Usage:
        @app.get("/endpoint")
        def endpoint(db: Session = Depends(get_db)):
            # use db here
    """
    SessionFactory = get_session_factory()
    db = SessionFactory()
    try:
        yield db
    finally:
        db.close()


def init_db(engine=None) -> None:
    """Initialize the database by creating all tables.

    Args:
        engine: Optional SQLAlchemy engine. If None, uses the application engine.

    This should be called explicitly during setup, not automatically on import.
    Safe to call multiple times (CREATE TABLE IF NOT EXISTS).
    """
    if engine is None:
        engine = get_engine()

    # Import models to ensure they are registered with Base.metadata
    from app.db import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
