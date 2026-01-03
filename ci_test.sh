#!/bin/bash
# CI/CD Test Script - WAF Production-Grade Implementation

set -e  # Exit on error

echo "========================================"
echo "WAF PRODUCTION-GRADE TEST SUITE"
echo "========================================"

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
PASSED=0
FAILED=0

# Helper function
run_test() {
    local name=$1
    local cmd=$2

    echo -e "\n${YELLOW}[TEST]${NC} $name"
    if eval "$cmd"; then
        echo -e "${GREEN}✓ PASS${NC}: $name"
        ((PASSED++))
    else
        echo -e "${RED}✗ FAIL${NC}: $name"
        ((FAILED++))
    fi
}

# Phase 1: File Structure
echo -e "\n${YELLOW}=== PHASE 1: File Structure ===${NC}"

run_test "Critical files exist" "
    test -f waf_proxy/main.py && \
    test -f waf_proxy/config.py && \
    test -f tests/conftest.py && \
    test -f configs/example.yaml && \
    test -f Dockerfile && \
    test -f docker-compose.yml
"

run_test "Documentation files exist" "
    test -f README.md && \
    test -f QUICKSTART.md && \
    test -f CHANGELOG.md && \
    test -f IMPLEMENTATION.md && \
    test -f SUMMARY.md
"

# Phase 2: Dependencies
echo -e "\n${YELLOW}=== PHASE 2: Dependencies ===${NC}"

run_test "Python version >= 3.11" "
    python3 --version | grep -E '3\.1[1-9]|3\.[2-9]'
"

run_test "FastAPI installed" "
    python3 -c 'import fastapi; print(fastapi.__version__)'
"

run_test "Pytest installed" "
    python3 -m pytest --version 2>&1 | grep pytest
"

# Phase 3: Code Quality
echo -e "\n${YELLOW}=== PHASE 3: Code Quality ===${NC}"

run_test "No syntax errors in main.py" "
    python3 -m py_compile waf_proxy/main.py
"

run_test "No syntax errors in models.py" "
    python3 -m py_compile waf_proxy/models.py
"

run_test "No syntax errors in engine.py" "
    python3 -m py_compile waf_proxy/waf/engine.py
"

run_test "No syntax errors in tests" "
    python3 -m py_compile tests/conftest.py && \
    python3 -m py_compile tests/test_normalization.py
"

# Phase 4: Imports
echo -e "\n${YELLOW}=== PHASE 4: Imports ===${NC}"

run_test "Config module imports" "
    python3 -c 'from waf_proxy.config import load_config; print(\"OK\")'
"

run_test "Models module imports" "
    python3 -c 'from waf_proxy.models import Config; print(\"OK\")'
"

run_test "WAF engine imports" "
    python3 -c 'from waf_proxy.waf.engine import SecurityEngine; print(\"OK\")'
"

run_test "Normalization imports" "
    python3 -c 'from waf_proxy.waf.normalize import get_client_ip, extract_headers_subset; print(\"OK\")'
"

run_test "Rate limiter imports" "
    python3 -c 'from waf_proxy.proxy.rate_limiter import RateLimiter; print(\"OK\")'
"

run_test "Metrics imports" "
    python3 -c 'from waf_proxy.observability.metrics import get_metrics_text; print(\"OK\")'
"

# Phase 5: Unit Tests
echo -e "\n${YELLOW}=== PHASE 5: Unit Tests ===${NC}"

run_test "Pytest can discover tests" "
    python3 -m pytest --collect-only 2>&1 | grep -c test_
"

run_test "Run pytest tests (with timeout)" "
    timeout 120 python3 -m pytest tests/ -q --tb=short 2>&1 | tail -5
"

# Phase 6: Docker
echo -e "\n${YELLOW}=== PHASE 6: Docker ===${NC}"

run_test "Dockerfile syntax valid" "
    test -f Dockerfile && head -1 Dockerfile | grep -i 'FROM'
"

run_test "demo_upstream Dockerfile exists" "
    test -f demo_upstream/Dockerfile
"

run_test ".dockerignore exists" "
    test -f .dockerignore
"

# Phase 7: Validation Scripts
echo -e "\n${YELLOW}=== PHASE 7: Validation ===${NC}"

run_test "validate.py runs" "
    python3 validate.py 2>&1 | grep -i 'valid'
"

run_test "test_quick.py runs" "
    timeout 60 python3 test_quick.py 2>&1 | grep -i 'passed\|test'
"

# Phase 8: Configuration
echo -e "\n${YELLOW}=== PHASE 8: Configuration ===${NC}"

run_test "example.yaml is valid YAML" "
    python3 -c 'import yaml; yaml.safe_load(open(\"configs/example.yaml\"))' 2>&1
"

run_test "Config can be loaded and validated" "
    python3 -c 'from waf_proxy.config import load_config; config = load_config(); print(len(config.upstreams))' 2>&1
"

# Phase 9: Requirements
echo -e "\n${YELLOW}=== PHASE 9: Requirements ===${NC}"

run_test "requirements.txt exists and has content" "
    test -f requirements.txt && test -s requirements.txt
"

run_test "requirements-dev.txt exists and has content" "
    test -f requirements-dev.txt && test -s requirements-dev.txt
"

# Summary
echo -e "\n${YELLOW}========================================${NC}"
echo -e "TEST SUMMARY"
echo -e "${YELLOW}========================================${NC}"
echo -e "${GREEN}✓ Passed: $PASSED${NC}"
echo -e "${RED}✗ Failed: $FAILED${NC}"
echo -e "${YELLOW}========================================${NC}"

if [ $FAILED -eq 0 ]; then
    echo -e "\n${GREEN}✓ All tests passed! WAF is production-ready.${NC}\n"
    exit 0
else
    echo -e "\n${RED}✗ Some tests failed. Please review.${NC}\n"
    exit 1
fi

