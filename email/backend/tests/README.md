# SOCShield Backend Testing

## 🧪 Test Suite Overview

This directory contains comprehensive tests for the SOCShield backend system.

### Test Structure

```
tests/
├── conftest.py              # Pytest fixtures and configuration
├── test_api.py             # API endpoint tests
├── test_ai_providers.py    # AI provider tests (Gemini, OpenAI, Claude)
├── test_phishing_detector.py  # Phishing detection logic tests
├── test_ioc_extractor.py   # IOC extraction tests
├── test_config.py          # Configuration tests
└── test_integration.py     # Integration tests
```

## 🚀 Running Tests

### Quick Start

```bash
# Navigate to backend directory
cd backend

# Install test dependencies
pip install -r requirements.txt

# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=app --cov-report=html -v
```

### Using the Test Script

```bash
# Make the script executable
chmod +x run_tests.sh

# Run all tests
./run_tests.sh all

# Run only unit tests
./run_tests.sh unit

# Run only integration tests
./run_tests.sh integration

# Run with coverage report
./run_tests.sh coverage

# Run specific test
./run_tests.sh specific tests/test_api.py::TestHealthEndpoint::test_health_check
```

## 📊 Test Categories

### Unit Tests
Tests individual components in isolation:
- API endpoints
- AI providers
- Phishing detection logic
- IOC extraction
- Configuration

```bash
pytest tests/ -m "not integration" -v
```

### Integration Tests
Tests complete workflows:
- End-to-end phishing detection
- Email processing pipeline
- Alert generation
- Database operations

```bash
pytest tests/ -m "integration" -v
```

## 🎯 Test Coverage

Generate coverage reports:

```bash
# HTML report
pytest tests/ --cov=app --cov-report=html

# Terminal report
pytest tests/ --cov=app --cov-report=term-missing

# XML report (for CI/CD)
pytest tests/ --cov=app --cov-report=xml
```

View HTML coverage report:
```bash
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
```

## 🔧 Test Configuration

### pytest.ini
Configure pytest behavior:
- Test discovery patterns
- Coverage settings
- Markers for test categorization
- Timeout settings

### conftest.py
Shared fixtures:
- `test_db`: Test database session
- `client`: FastAPI test client
- `sample_phishing_email`: Phishing email test data
- `sample_legitimate_email`: Legitimate email test data
- `mock_ai_api_key`: Mock API key for testing

## 📝 Writing Tests

### Test Structure

```python
import pytest

class TestYourFeature:
    """Test your feature"""
    
    def test_something(self, client):
        """Test description"""
        response = client.get("/api/v1/endpoint")
        assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_async_function(self):
        """Test async function"""
        result = await some_async_function()
        assert result is not None
```

### Using Fixtures

```python
def test_with_fixtures(self, client, sample_phishing_email):
    """Use predefined fixtures"""
    response = client.post("/api/v1/analyze", json=sample_phishing_email)
    assert response.status_code == 200
```

### Mocking External Services

```python
from unittest.mock import Mock, patch

@patch('app.ai.gemini_provider.genai.GenerativeModel')
def test_with_mock(self, mock_model):
    """Test with mocked external service"""
    mock_model.return_value.generate_content.return_value = Mock(text='{"result": "test"}')
    # Your test code
```

## 🧩 Test Examples

### API Endpoint Test

```python
def test_health_endpoint(self, client):
    """Test health check endpoint"""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
```

### Phishing Detection Test

```python
@pytest.mark.asyncio
async def test_detect_phishing(self, sample_phishing_email):
    """Test phishing detection"""
    detector = PhishingDetector()
    result = await detector.analyze(sample_phishing_email)
    assert result["is_phishing"] == True
    assert result["confidence"] > 0.7
```

### IOC Extraction Test

```python
def test_extract_urls(self, extractor):
    """Test URL extraction"""
    text = "Visit https://example.com or http://test.org"
    urls = extractor.extract_urls(text)
    assert len(urls) == 2
```

## 🔍 Testing Best Practices

1. **Test Isolation**: Each test should be independent
2. **Clear Names**: Use descriptive test names
3. **Arrange-Act-Assert**: Structure tests clearly
4. **Mock External Services**: Don't make real API calls
5. **Test Edge Cases**: Include boundary conditions
6. **Use Fixtures**: Reuse common test data
7. **Fast Tests**: Keep tests quick to run
8. **Comprehensive Coverage**: Aim for >80% coverage

## 🐛 Debugging Tests

### Run specific test
```bash
pytest tests/test_api.py::TestHealthEndpoint::test_health_check -v
```

### Show print statements
```bash
pytest tests/ -v -s
```

### Debug with pdb
```bash
pytest tests/ --pdb
```

### Show local variables on failure
```bash
pytest tests/ -v -l
```

## 🔄 Continuous Integration

### GitHub Actions Example

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: pytest tests/ --cov=app --cov-report=xml
      - uses: codecov/codecov-action@v2
```

## 📈 Test Metrics

Target metrics:
- **Code Coverage**: >80%
- **Test Execution Time**: <5 minutes
- **Test Pass Rate**: 100%
- **Flaky Tests**: 0

## 🔐 Testing with API Keys

For tests that require real API keys:

```bash
# Set environment variables
export GOOGLE_API_KEY="your-key"
export OPENAI_API_KEY="your-key"

# Run tests requiring API keys
pytest tests/ -m "requires_api" -v
```

## 📚 Additional Resources

- [Pytest Documentation](https://docs.pytest.org/)
- [FastAPI Testing](https://fastapi.tiangolo.com/tutorial/testing/)
- [Testing Async Code](https://pytest-asyncio.readthedocs.io/)
- [Coverage.py](https://coverage.readthedocs.io/)
