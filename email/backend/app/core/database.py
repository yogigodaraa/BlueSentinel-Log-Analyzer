"""
Database Configuration
SQLAlchemy setup for PostgreSQL with async support
"""

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy import MetaData
from sqlalchemy.pool import StaticPool
from app.core.config import settings

# Create async engine
# Handle both PostgreSQL and SQLite
database_url = settings.DATABASE_URL

if database_url.startswith('sqlite'):
    # For SQLite - use aiosqlite with StaticPool
    if not database_url.startswith('sqlite+aiosqlite'):
        database_url = database_url.replace('sqlite://', 'sqlite+aiosqlite://')
    
    engine = create_async_engine(
        database_url,
        echo=settings.DEBUG,
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
else:
    # For PostgreSQL - use asyncpg with connection pooling
    if database_url.startswith('postgresql://'):
        database_url = database_url.replace('postgresql://', 'postgresql+asyncpg://')
    
    engine = create_async_engine(
        database_url,
        echo=settings.DEBUG,
        future=True,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
    )

# Create session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False
)

# Create base class for models
metadata = MetaData()
Base = declarative_base(metadata=metadata)


# Dependency to get database session
async def get_db():
    """Database session dependency"""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
