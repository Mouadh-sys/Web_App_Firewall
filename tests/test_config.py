"""Test configuration for WAF proxy."""
import os
import tempfile
import yaml

# Create a test configuration file in memory
TEST_CONFIG = {
    'upstreams': [
        {
            'name': 'test_upstream',
            'url': 'http://localhost:9999',  # Won't connect, will be mocked
            'weight': 1
        }
    ],
    'ip_allowlist': ['127.0.0.1', '::1'],
    'ip_blocklist': [],
    'trusted_proxies': ['127.0.0.1', '::1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
    'rules': [
        {
            'id': 'PT001',
            'description': 'Path traversal indicators',
            'target': 'path',
            'pattern': r'(?i)(\.\./|%2e%2e%2f|%2e%2e\\)',
            'score': 10,
            'enabled': True
        },
        {
            'id': 'SQLI001',
            'description': 'SQL injection indicators',
            'target': 'query',
            'pattern': r'(?i)(union\s+select|or\s+1=1|sleep\(|benchmark\(|--|;--|/\*|\*/)',
            'score': 8,
            'enabled': True
        }
    ],
    'thresholds': {
        'allow': 5,
        'challenge': 6,
        'block': 10
    },
    'rate_limits': {
        'requests_per_minute': 60
    },
    'proxy_settings': {
        'timeout_seconds': 5.0,
        'max_connections': 10,
        'max_keepalive_connections': 5,
        'keepalive_expiry': 5.0,
        'retries': 0
    },
    'waf_settings': {
        'mode': 'block',
        'max_inspect_bytes': 10000,
        'max_body_bytes': 1000000,
        'inspect_body': False
    }
}


def get_test_config_path():
    """Get path to test configuration."""
    # Create temporary config file
    fd, path = tempfile.mkstemp(suffix='.yaml', prefix='test_config_')
    with os.fdopen(fd, 'w') as f:
        yaml.dump(TEST_CONFIG, f)
    return path


def setup_test_config():
    """Setup test configuration environment."""
    config_path = get_test_config_path()
    os.environ['CONFIG_PATH'] = config_path
    return config_path

