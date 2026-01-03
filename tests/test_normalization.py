"""Tests for request normalization and trusted proxy handling."""
import pytest
from waf_proxy.waf.normalize import (
    normalize_path,
    normalize_query,
    get_client_ip,
    extract_headers_subset,
    build_inspection_dict
)


class DummyHeaders:
    """Mock headers dict that is case-insensitive like FastAPI."""

    def __init__(self, headers_dict):
        self._headers = {k.lower(): v for k, v in (headers_dict or {}).items()}

    def get(self, key, default=None):
        return self._headers.get(key.lower(), default)


class DummyRequest:
    """Mock FastAPI request."""

    def __init__(self, path='/', query='', headers=None, client_host='1.2.3.4'):
        self.url = type('u', (), {'path': path, 'query': query})
        self.headers = DummyHeaders(headers)
        self.client = type('c', (), {'host': client_host})


class TestPathNormalization:
    """Test path normalization."""

    def test_path_decode_and_normalize(self):
        """Test URL decoding and normalization."""
        assert normalize_path('/%2e%2e/etc/passwd') == '/etc/passwd'
        assert normalize_path('/../etc/passwd') == '/etc/passwd'
        assert normalize_path('/test//path') == '/test/path'
        assert normalize_path('/test\\path') == '/test/path'

    def test_path_null_byte_removal(self):
        """Test null byte removal."""
        assert normalize_path('/test\x00payload') == '/testpayload'

    def test_path_preserve_leading_slash(self):
        """Test that leading slash is preserved."""
        assert normalize_path('test').startswith('/')
        assert normalize_path('/test').startswith('/')


class TestQueryNormalization:
    """Test query string normalization."""

    def test_query_decode(self):
        """Test query decoding."""
        assert normalize_query('q=%2e%2e') == 'q=..'

    def test_query_empty(self):
        """Test empty query."""
        assert normalize_query('') == ''
        assert normalize_query(None) == ''


class TestClientIPExtraction:
    """Test client IP extraction with trusted proxies."""

    def test_client_ip_without_trusted_proxies(self):
        """Test that peer IP is used when no trusted proxies configured."""
        request = DummyRequest(
            client_host='1.2.3.4',
            headers={'x-forwarded-for': '5.6.7.8'}
        )
        ip = get_client_ip(request, trusted_proxies=None)
        assert ip == '1.2.3.4'

    def test_client_ip_xff_from_untrusted_source(self):
        """Test that X-Forwarded-For is ignored from untrusted sources."""
        request = DummyRequest(
            client_host='9.8.7.6',
            headers={'x-forwarded-for': '1.2.3.4'}
        )
        ip = get_client_ip(request, trusted_proxies=['10.0.0.0/8'])
        # Peer IP 9.8.7.6 is not in trusted list, so ignore XFF
        assert ip == '9.8.7.6'

    def test_client_ip_xff_from_trusted_proxy(self):
        """Test that X-Forwarded-For is used from trusted proxies."""
        request = DummyRequest(
            client_host='10.0.0.5',
            headers={'x-forwarded-for': '1.2.3.4'}
        )
        ip = get_client_ip(request, trusted_proxies=['10.0.0.0/8'])
        # Peer IP is trusted, use XFF
        assert ip == '1.2.3.4'

    def test_client_ip_xff_multiple_proxies(self):
        """Test X-Forwarded-For with multiple proxy hops."""
        request = DummyRequest(
            client_host='10.0.0.5',
            headers={'x-forwarded-for': '1.2.3.4, 10.0.0.1'}
        )
        ip = get_client_ip(request, trusted_proxies=['10.0.0.0/8'])
        # Take the left-most (first) IP
        assert ip == '1.2.3.4'


class TestHeaderExtraction:
    """Test header extraction for inspection."""

    def test_header_extraction(self):
        """Test that relevant headers are extracted."""
        request = DummyRequest(
            headers={
                'user-agent': 'curl/1.0',
                'referer': 'http://example.com',
                'content-type': 'application/json'
            }
        )
        headers = extract_headers_subset(request)

        assert 'user-agent:curl/1.0' in headers.lower()
        assert 'referer:http://example.com' in headers.lower()
        assert 'content-type:application/json' in headers.lower()

    def test_header_lowercased(self):
        """Test that headers are lowercased for matching."""
        request = DummyRequest(
            headers={'User-Agent': 'sqlmap'}
        )
        headers = extract_headers_subset(request)
        assert 'user-agent:sqlmap' in headers.lower()


class TestInspectionDict:
    """Test inspection dict building."""

    def test_inspection_dict_complete(self):
        """Test that inspection dict has required fields."""
        request = DummyRequest(path='/test', query='q=value')
        inspection = build_inspection_dict(request)

        assert 'path' in inspection
        assert 'query' in inspection
        assert 'headers' in inspection
        assert inspection['path'] == '/test'
        assert 'q=value' in inspection['query']

    def test_inspection_dict_truncation(self):
        """Test that inspection dict is truncated to avoid DoS."""
        long_path = '/test' * 10000
        request = DummyRequest(path=long_path)
        inspection = build_inspection_dict(request, max_inspect_bytes=100)

        assert len(inspection['path']) <= 100

