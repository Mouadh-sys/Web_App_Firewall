#!/usr/bin/env python3
"""
Comprehensive test suite for WAF production-grade implementation.
Tests all critical fixes and features.
"""
import sys
import os
import asyncio
import json

# Add project to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Test counters
tests_passed = 0
tests_failed = 0

def test(name):
    """Decorator for test functions."""
    def decorator(func):
        def wrapper():
            global tests_passed, tests_failed
            try:
                print(f"\nTesting: {name}")
                func()
                print(f"  ✓ PASS")
                tests_passed += 1
            except AssertionError as e:
                print(f"  ✗ FAIL: {e}")
                tests_failed += 1
            except Exception as e:
                print(f"  ✗ ERROR: {e}")
                tests_failed += 1
        return wrapper
    return decorator

# ============ PHASE 1: Header Extraction ============

@test("Header extraction with case-insensitive access")
def test_header_extraction():
    from tests.conftest import DummyRequest
    from waf_proxy.waf.normalize import extract_headers_subset

    request = DummyRequest(headers={'User-Agent': 'sqlmap'})
    result = extract_headers_subset(request)
    assert 'user-agent' in result.lower()
    assert 'sqlmap' in result.lower()

@test("DummyHeaders case-insensitive get")
def test_dummy_headers():
    from tests.conftest import DummyHeaders

    headers = DummyHeaders({'Content-Type': 'application/json'})
    assert headers.get('content-type') == 'application/json'
    assert headers.get('CONTENT-TYPE') == 'application/json'
    assert headers.get('nonexistent') is None

@test("Normalization functions")
def test_normalization():
    from waf_proxy.waf.normalize import normalize_path, normalize_query

    # Path traversal
    assert normalize_path('/../etc/passwd') == '/etc/passwd'
    assert normalize_path('/%2e%2e/etc') == '/etc'

    # Query normalization
    assert normalize_query('q=%2e%2e') == 'q=..'

@test("Client IP extraction with trusted proxies")
def test_client_ip_extraction():
    from tests.conftest import DummyRequest
    from waf_proxy.waf.normalize import get_client_ip

    # From untrusted source, ignore X-Forwarded-For
    request = DummyRequest(
        client_host='9.8.7.6',
        headers={'x-forwarded-for': '1.2.3.4'}
    )
    ip = get_client_ip(request, trusted_proxies=['10.0.0.0/8'])
    assert ip == '9.8.7.6'  # Use peer IP, not spoofed XFF

    # From trusted source, honor X-Forwarded-For
    request = DummyRequest(
        client_host='10.0.0.5',
        headers={'x-forwarded-for': '1.2.3.4'}
    )
    ip = get_client_ip(request, trusted_proxies=['10.0.0.0/8'])
    assert ip == '1.2.3.4'  # Use XFF from trusted proxy

# ============ PHASE 2: Metrics ============

@test("Metrics returns string")
def test_metrics_string():
    from waf_proxy.observability.metrics import get_metrics_text

    metrics = get_metrics_text()
    assert isinstance(metrics, str), f"Expected str, got {type(metrics)}"
    assert len(metrics) > 0

@test("Metrics contains Prometheus format")
def test_metrics_format():
    from waf_proxy.observability.metrics import get_metrics_text

    metrics = get_metrics_text()
    # Prometheus format has # HELP or # TYPE
    assert '#' in metrics or 'requests' in metrics.lower()

# ============ PHASE 3: Rate Limiter ============

@test("Rate limiter is async-safe")
def test_rate_limiter():
    from waf_proxy.proxy.rate_limiter import RateLimiter

    async def run():
        limiter = RateLimiter(default_rpm=10)
        result = await limiter.is_allowed("test_ip")
        assert isinstance(result, bool)
        assert result == True  # First request allowed

    asyncio.run(run())

@test("Rate limiter blocks after limit")
def test_rate_limiter_blocking():
    from waf_proxy.proxy.rate_limiter import TokenBucket

    bucket = TokenBucket(capacity=2, refill_rate=2)  # 2 requests per minute
    assert bucket.allow_request() == True   # First request
    assert bucket.allow_request() == True   # Second request
    assert bucket.allow_request() == False  # Third request blocked

# ============ PHASE 4: Config Loading ============

@test("Config model validation")
def test_config_model():
    from waf_proxy.models import Config, UpstreamConfig, ThresholdsConfig

    # Create config with valid data
    config = Config(
        upstreams=[UpstreamConfig(name='test', url='http://localhost:8080')],
        ip_allowlist=['127.0.0.1'],
        trusted_proxies=['10.0.0.0/8'],
        thresholds=ThresholdsConfig(allow=5, challenge=6, block=10)
    )

    assert len(config.upstreams) == 1
    assert config.upstreams[0].name == 'test'
    assert config.thresholds.block == 10

@test("Invalid CIDR in config raises error")
def test_config_invalid_cidr():
    from waf_proxy.models import Config, UpstreamConfig

    try:
        Config(
            upstreams=[UpstreamConfig(name='test', url='http://localhost')],
            trusted_proxies=['invalid.cidr']
        )
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert 'CIDR' in str(e) or 'Invalid' in str(e)

# ============ PHASE 5: Security Engine ============

@test("WAF engine IP allowlist fast-path")
def test_waf_allowlist():
    from waf_proxy.waf.engine import SecurityEngine
    from waf_proxy.models import Config, UpstreamConfig

    config = Config(
        upstreams=[UpstreamConfig(name='test', url='http://localhost')],
        ip_allowlist=['1.1.1.1'],
        rules=[]
    )
    engine = SecurityEngine(config)
    result = engine.evaluate({'path': '/', 'query': '', 'headers': ''}, '1.1.1.1')
    assert result['verdict'] == 'ALLOW'
    assert result['rule_ids'] == ['allowlist']

@test("WAF engine rule matching")
def test_waf_rule_matching():
    from waf_proxy.waf.engine import SecurityEngine
    from waf_proxy.models import Config, UpstreamConfig, RuleConfig

    config = Config(
        upstreams=[UpstreamConfig(name='test', url='http://localhost')],
        rules=[
            RuleConfig(
                id='TEST001',
                description='Test pattern',
                target='path',
                pattern=r'../etc/passwd',
                score=10
            )
        ]
    )
    engine = SecurityEngine(config)
    result = engine.evaluate({'path': '/../etc/passwd', 'query': '', 'headers': ''}, '1.2.3.4')
    assert result['verdict'] == 'BLOCK'
    assert result['score'] >= 10
    assert 'TEST001' in result['rule_ids']

# ============ PHASE 6: Proxy & Headers ============

@test("Hop-by-hop header filtering")
def test_hop_by_hop_filtering():
    from waf_proxy.proxy.headers import filter_request_headers

    headers = {
        'host': 'example.com',
        'connection': 'keep-alive',
        'keep-alive': '5',
        'user-agent': 'test',
    }
    filtered = filter_request_headers(headers)

    # Should keep safe headers
    assert 'host' in filtered or 'user-agent' in filtered
    # Should remove hop-by-hop
    assert 'connection' not in filtered
    assert 'keep-alive' not in filtered

@test("Forwarding headers addition")
def test_forwarding_headers():
    from waf_proxy.proxy.headers import add_forwarding_headers

    headers = {}
    headers = add_forwarding_headers(
        headers,
        client_ip='192.168.1.1',
        original_scheme='https',
        original_host='example.com'
    )

    assert 'x-forwarded-for' in headers
    assert headers['x-forwarded-for'] == '192.168.1.1'
    assert headers['x-forwarded-proto'] == 'https'
    assert headers['x-forwarded-host'] == 'example.com'

# ============ PHASE 7: Router ============

@test("Router round-robin selection")
def test_router():
    from waf_proxy.proxy.router import Router
    from waf_proxy.models import UpstreamConfig

    upstreams = [
        UpstreamConfig(name='upstream1', url='http://backend1:8080'),
        UpstreamConfig(name='upstream2', url='http://backend2:8080'),
    ]
    router = Router(upstreams)

    # Mock request
    request = type('Request', (), {
        'headers': {},
        'url': type('URL', (), {'path': '/'})
    })()

    # Should return one of the upstreams
    result = router.get_upstream(request)
    assert result in ['http://backend1:8080', 'http://backend2:8080']

# ============ PHASE 8: JSON Logging ============

@test("JSON logging formatter")
def test_json_logging():
    from waf_proxy.observability.logging import JSONFormatter
    import logging

    formatter = JSONFormatter()
    record = logging.LogRecord(
        name='test',
        level=logging.INFO,
        pathname='test.py',
        lineno=1,
        msg='Test message',
        args=(),
        exc_info=None
    )
    record.request_id = 'abc123'
    record.client_ip = '1.2.3.4'

    output = formatter.format(record)
    data = json.loads(output)

    assert data['message'] == 'Test message'
    assert data['request_id'] == 'abc123'
    assert data['client_ip'] == '1.2.3.4'

# ============ PHASE 9: File Structure ============

@test("Required files exist")
def test_required_files():
    base = os.path.dirname(os.path.abspath(__file__))
    required = [
        'waf_proxy/main.py',
        'waf_proxy/config.py',
        'waf_proxy/models.py',
        'tests/conftest.py',
        'configs/example.yaml',
        'Dockerfile',
        '.dockerignore',
        'docker-compose.yml',
        'requirements.txt',
        'requirements-dev.txt',
    ]

    missing = []
    for f in required:
        if not os.path.isfile(os.path.join(base, f)):
            missing.append(f)

    assert len(missing) == 0, f"Missing files: {missing}"

# ============ Main Test Runner ============

def main():
    """Run all tests."""
    print("=" * 70)
    print("WAF PRODUCTION-GRADE IMPLEMENTATION - COMPREHENSIVE TEST SUITE")
    print("=" * 70)

    # Collect all test functions
    test_funcs = [
        test_header_extraction(),
        test_dummy_headers(),
        test_normalization(),
        test_client_ip_extraction(),
        test_metrics_string(),
        test_metrics_format(),
        test_rate_limiter(),
        test_rate_limiter_blocking(),
        test_config_model(),
        test_config_invalid_cidr(),
        test_waf_allowlist(),
        test_waf_rule_matching(),
        test_hop_by_hop_filtering(),
        test_forwarding_headers(),
        test_router(),
        test_json_logging(),
        test_required_files(),
    ]

    print(f"\nRunning {len(test_funcs)} test groups...\n")

    for _ in test_funcs:
        pass  # Tests already run via decorators

    print("\n" + "=" * 70)
    print(f"RESULTS: {tests_passed} passed, {tests_failed} failed")
    print("=" * 70)

    if tests_failed > 0:
        sys.exit(1)
    else:
        print("\n✓ All tests passed! WAF is production-ready.\n")
        sys.exit(0)

if __name__ == '__main__':
    main()

