"""
Pytest configuration and fixtures
"""
import pytest
import asyncio
from typing import AsyncGenerator, Generator
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool

from app.main import app
from app.core.database import Base, get_db

# Test database URL
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create an event loop for the test session"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="function")
async def test_db() -> AsyncGenerator[AsyncSession, None]:
    """Create a test database session"""
    engine = create_async_engine(
        TEST_DATABASE_URL,
        poolclass=NullPool,
    )
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    async_session_maker = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    
    async with async_session_maker() as session:
        yield session
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    
    await engine.dispose()


@pytest.fixture(scope="function")
def client(test_db: AsyncSession) -> TestClient:
    """Create a test client"""
    
    async def override_get_db():
        yield test_db
    
    app.dependency_overrides[get_db] = override_get_db
    
    with TestClient(app) as test_client:
        yield test_client
    
    app.dependency_overrides.clear()


@pytest.fixture
def sample_phishing_email():
    """Sample phishing email for testing"""
    return {
        "subject": "Urgent: Your PayPal Account Has Been Limited",
        "sender": "security@paypa1-secure.com",
        "body": "Dear Valued Customer,\n\nYour PayPal account has been temporarily limited due to unusual activity. To restore full access, please verify your identity immediately by clicking the link below:\n\nhttps://secure-paypal-verify.tk/account/login\n\nFailure to complete verification within 24 hours will result in permanent account suspension.\n\nSincerely,\nPayPal Security Team",
        "links": ["https://secure-paypal-verify.tk/account/login"],
        "received_date": "2024-10-15T10:30:00Z"
    }


@pytest.fixture
def sample_legitimate_email():
    """Sample legitimate email for testing"""
    return {
        "subject": "Team Meeting - Q4 Planning",
        "sender": "manager@yourcompany.com",
        "body": "Hi team,\n\nLet's schedule our Q4 planning meeting for next Tuesday at 2 PM. Please review the agenda document before the meeting.\n\nBest regards,\nJohn",
        "received_date": "2024-10-15T10:30:00Z"
    }


@pytest.fixture
def sample_microsoft_phishing():
    """Sample Microsoft phishing email"""
    return {
        "subject": "Action Required: Verify Your Microsoft Account",
        "sender": "no-reply@microsoft-security.xyz",
        "body": "Your Microsoft 365 account requires immediate verification. Click below to confirm your identity:\n\nhttps://login-microsoftonline.tk/signin\n\nIf you don't verify within 2 hours, your account will be suspended.",
        "links": ["https://login-microsoftonline.tk/signin"],
        "received_date": "2024-10-15T11:00:00Z"
    }


@pytest.fixture
def mock_ai_api_key():
    """Mock API key for testing"""
    return "test_api_key_12345"
