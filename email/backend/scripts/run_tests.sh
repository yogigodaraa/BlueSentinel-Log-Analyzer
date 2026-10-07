#!/bin/bash

# SOCShield Backend Test Runner
# This script runs different types of tests for the backend

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🧪 SOCShield Backend Test Suite${NC}"
echo "=================================="

# Check if pytest is installed
if ! command -v pytest &> /dev/null; then
    echo -e "${RED}❌ pytest not found. Installing dependencies...${NC}"
    pip install -r requirements.txt
fi

# Parse command line arguments
TEST_TYPE=${1:-all}
COVERAGE=${2:-yes}

case $TEST_TYPE in
    unit)
        echo -e "${YELLOW}Running unit tests only...${NC}"
        pytest tests/ -m "not integration" -v
        ;;
    
    integration)
        echo -e "${YELLOW}Running integration tests only...${NC}"
        pytest tests/ -m "integration" -v
        ;;
    
    fast)
        echo -e "${YELLOW}Running fast tests only...${NC}"
        pytest tests/ -m "not slow" -v
        ;;
    
    coverage)
        echo -e "${YELLOW}Running all tests with coverage report...${NC}"
        pytest tests/ --cov=app --cov-report=html --cov-report=term-missing -v
        echo -e "${GREEN}✓ Coverage report generated in htmlcov/index.html${NC}"
        ;;
    
    specific)
        if [ -z "$2" ]; then
            echo -e "${RED}❌ Please specify a test file or function${NC}"
            echo "Usage: ./run_tests.sh specific tests/test_api.py::TestHealthEndpoint::test_health_check"
            exit 1
        fi
        echo -e "${YELLOW}Running specific test: $2${NC}"
        pytest "$2" -v
        ;;
    
    all|*)
        echo -e "${YELLOW}Running all tests...${NC}"
        if [ "$COVERAGE" = "yes" ]; then
            pytest tests/ --cov=app --cov-report=html --cov-report=term -v
            echo -e "${GREEN}✓ Coverage report generated in htmlcov/index.html${NC}"
        else
            pytest tests/ -v
        fi
        ;;
esac

# Check exit code
if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✅ All tests passed!${NC}"
    exit 0
else
    echo ""
    echo -e "${RED}❌ Some tests failed!${NC}"
    exit 1
fi
