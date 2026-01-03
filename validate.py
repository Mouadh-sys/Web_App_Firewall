#!/usr/bin/env python3
"""Validate WAF project structure and critical fixes."""
import os
import sys

def check_file_exists(path):
    """Check if file exists."""
    return os.path.isfile(path)

def check_dir_exists(path):
    """Check if directory exists."""
    return os.path.isdir(path)

def validate_structure():
    """Validate project structure."""
    base = os.path.dirname(os.path.abspath(__file__))

    # Critical files
    files_to_check = [
        'waf_proxy/__init__.py',
        'waf_proxy/main.py',
        'waf_proxy/config.py',
        'waf_proxy/models.py',
        'waf_proxy/middleware/__init__.py',
        'waf_proxy/middleware/waf_middleware.py',
        'waf_proxy/proxy/__init__.py',
        'waf_proxy/proxy/proxy_client.py',
        'waf_proxy/proxy/headers.py',
        'waf_proxy/proxy/rate_limiter.py',
        'waf_proxy/proxy/router.py',
        'waf_proxy/waf/__init__.py',
        'waf_proxy/waf/engine.py',
        'waf_proxy/waf/normalize.py',
        'waf_proxy/observability/__init__.py',
        'waf_proxy/observability/logging.py',
        'waf_proxy/observability/metrics.py',
        'tests/__init__.py',
        'tests/conftest.py',
        'tests/test_normalization.py',
        'tests/test_waf_engine.py',
        'tests/test_proxy_integration.py',
        'configs/example.yaml',
        'demo_upstream/Dockerfile',
        'demo_upstream/requirements.txt',
        'demo_upstream/app.py',
        'Dockerfile',
        '.dockerignore',
        'docker-compose.yml',
        'requirements.txt',
        'requirements-dev.txt',
        'README.md',
    ]

    print("Checking file structure...")
    missing = []
    for f in files_to_check:
        path = os.path.join(base, f)
        if not check_file_exists(path):
            print(f"  ✗ MISSING: {f}")
            missing.append(f)
        else:
            print(f"  ✓ {f}")

    if missing:
        print(f"\n✗ Missing {len(missing)} file(s)")
        return False

    print("\n✓ All required files present")
    return True

def check_imports():
    """Validate critical imports."""
    print("\nChecking imports...")
    try:
        from waf_proxy.models import Config
        print("  ✓ Config model imports")

        from waf_proxy.waf.engine import SecurityEngine
        print("  ✓ SecurityEngine imports")

        from waf_proxy.waf.normalize import get_client_ip, extract_headers_subset
        print("  ✓ Normalization functions import")

        from waf_proxy.proxy.rate_limiter import RateLimiter
        print("  ✓ RateLimiter imports")

        from waf_proxy.observability.metrics import get_metrics_text
        print("  ✓ Metrics imports")

        return True
    except Exception as e:
        print(f"  ✗ Import error: {e}")
        return False

if __name__ == '__main__':
    print("=" * 60)
    print("WAF Project Validation")
    print("=" * 60)

    struct_ok = validate_structure()
    imports_ok = check_imports()

    print("\n" + "=" * 60)
    if struct_ok and imports_ok:
        print("✓ Project structure and imports validated!")
        sys.exit(0)
    else:
        print("✗ Validation failed!")
        sys.exit(1)

