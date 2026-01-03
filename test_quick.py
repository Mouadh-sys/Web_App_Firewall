#!/usr/bin/env python3
"""Quick test runner to verify WAF fixes."""
import sys
import os

# Add project to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_header_extraction():
    """Test DummyHeaders and extract_headers_subset."""
    from tests.conftest import DummyRequest
    from waf_proxy.waf.normalize import extract_headers_subset

    # Test case-insensitive headers
    request = DummyRequest(headers={'User-Agent': 'sqlmap'})
    result = extract_headers_subset(request)

    print(f"✓ extract_headers_subset works: {repr(result)}")
    assert 'user-agent:sqlmap' in result.lower(), f"Expected user-agent in {repr(result)}"
    print("✓ Header extraction test passed")

def test_metrics():
    """Test metrics returns string."""
    from waf_proxy.observability.metrics import get_metrics_text

    metrics = get_metrics_text()
    print(f"✓ get_metrics_text returns: {type(metrics).__name__}")
    assert isinstance(metrics, str), f"Expected str, got {type(metrics)}"
    assert 'requests' in metrics.lower() or len(metrics) > 0
    print("✓ Metrics test passed")

def test_rate_limiter():
    """Test rate limiter basic functionality."""
    import asyncio
    from waf_proxy.proxy.rate_limiter import RateLimiter

    async def run_test():
        limiter = RateLimiter(default_rpm=10)
        # Should allow first requests
        result1 = await limiter.is_allowed("test_ip")
        assert result1, "First request should be allowed"
        print("✓ Rate limiter allows first request")

    asyncio.run(run_test())

def test_config_loading():
    """Test config loading."""
    from waf_proxy.config import load_config

    try:
        config = load_config()
        print(f"✓ Config loaded: {len(config.upstreams)} upstream(s)")
        assert len(config.upstreams) > 0
        assert config.thresholds is not None
        print("✓ Config test passed")
    except FileNotFoundError as e:
        print(f"⚠ Config test skipped (file not found): {e}")

if __name__ == '__main__':
    print("=" * 60)
    print("Running Quick WAF Tests")
    print("=" * 60)

    try:
        test_header_extraction()
        print()
        test_metrics()
        print()
        test_rate_limiter()
        print()
        test_config_loading()
        print()
        print("=" * 60)
        print("✓ All quick tests passed!")
        print("=" * 60)
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

