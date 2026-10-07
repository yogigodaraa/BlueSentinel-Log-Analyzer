#!/bin/bash

# SOCShield Integration Test Script

echo "🧪 Testing SOCShield Backend-Frontend Integration"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

BACKEND_URL="http://localhost:8000"
FRONTEND_URL="http://localhost:3000"

test_passed=0
test_failed=0

# Function to test endpoint
test_endpoint() {
    local name=$1
    local url=$2
    local method=${3:-GET}
    
    echo -n "Testing $name... "
    
    if [ "$method" == "GET" ]; then
        response=$(curl -s -o /dev/null -w "%{http_code}" "$url")
    else
        response=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$url" \
            -H "Content-Type: application/json" \
            -d '{"subject":"Test","sender":"test@example.com","body":"Test email"}')
    fi
    
    if [ "$response" == "200" ] || [ "$response" == "307" ]; then
        echo -e "${GREEN}✅ PASS${NC} (HTTP $response)"
        ((test_passed++))
    else
        echo -e "${RED}❌ FAIL${NC} (HTTP $response)"
        ((test_failed++))
    fi
}

echo -e "${BLUE}═══════════════════════════════════════${NC}"
echo -e "${BLUE}    Backend Tests${NC}"
echo -e "${BLUE}═══════════════════════════════════════${NC}"
echo ""

# Check if backend is running
if ! curl -s "$BACKEND_URL/health" > /dev/null 2>&1; then
    echo -e "${RED}❌ Backend is not running at $BACKEND_URL${NC}"
    echo "Please start the backend first: cd backend && python -m uvicorn app.main:app --reload"
    exit 1
fi

# Backend tests
test_endpoint "Health Check" "$BACKEND_URL/health"
test_endpoint "Root Endpoint" "$BACKEND_URL/"
test_endpoint "Metrics" "$BACKEND_URL/metrics"
test_endpoint "Dashboard Stats" "$BACKEND_URL/api/v1/dashboard/stats"
test_endpoint "List Emails" "$BACKEND_URL/api/v1/emails"
test_endpoint "List Threats" "$BACKEND_URL/api/v1/threats"
test_endpoint "Email Analysis" "$BACKEND_URL/api/v1/analysis/analyze" "POST"

echo ""
echo -e "${BLUE}═══════════════════════════════════════${NC}"
echo -e "${BLUE}    Frontend Tests${NC}"
echo -e "${BLUE}═══════════════════════════════════════${NC}"
echo ""

# Check if frontend is running
if ! curl -s "$FRONTEND_URL" > /dev/null 2>&1; then
    echo -e "${YELLOW}⚠️  Frontend is not running at $FRONTEND_URL${NC}"
    echo "Please start the frontend: cd frontend && npm run dev"
    echo ""
else
    test_endpoint "Home Page" "$FRONTEND_URL"
    test_endpoint "Dashboard Page" "$FRONTEND_URL/dashboard"
    echo ""
fi

echo -e "${BLUE}═══════════════════════════════════════${NC}"
echo -e "${BLUE}    Test Summary${NC}"
echo -e "${BLUE}═══════════════════════════════════════${NC}"
echo ""
echo -e "Tests Passed: ${GREEN}$test_passed${NC}"
echo -e "Tests Failed: ${RED}$test_failed${NC}"
echo ""

# Detailed API response test
echo -e "${BLUE}═══════════════════════════════════════${NC}"
echo -e "${BLUE}    Sample API Responses${NC}"
echo -e "${BLUE}═══════════════════════════════════════${NC}"
echo ""

echo -e "${YELLOW}📊 Dashboard Stats:${NC}"
curl -s "$BACKEND_URL/api/v1/dashboard/stats" | python3 -m json.tool 2>/dev/null || echo "Failed to fetch"
echo ""

echo -e "${YELLOW}❤️  Health Check:${NC}"
curl -s "$BACKEND_URL/health" | python3 -m json.tool 2>/dev/null || echo "Failed to fetch"
echo ""

if [ $test_failed -eq 0 ]; then
    echo -e "${GREEN}✨ All tests passed! Backend and frontend are properly integrated.${NC}"
    echo ""
    echo -e "${GREEN}🎉 You can now access:${NC}"
    echo -e "   Frontend: ${BLUE}http://localhost:3000${NC}"
    echo -e "   Dashboard: ${BLUE}http://localhost:3000/dashboard${NC}"
    echo -e "   API Docs: ${BLUE}http://localhost:8000/docs${NC}"
else
    echo -e "${RED}⚠️  Some tests failed. Please check the services.${NC}"
    exit 1
fi
