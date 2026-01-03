"""Pytest configuration and shared fixtures for WAF tests."""
import pytest
from unittest.mock import Mock, AsyncMock, patch
from fastapi.testclient import TestClient
from waf_proxy.main import app
from waf_proxy.models import Config, UpstreamConfig

# Make fixtures available to all tests
pytest_plugins = []


class DummyHeaders:
    """Mock headers dict that is case-insensitive like FastAPI."""

    def __init__(self, headers_dict):
        self._headers = {k.lower(): v for k, v in (headers_dict or {}).items()}

    def get(self, key, default=None):
        return self._headers.get(key.lower(), default)

    def items(self):
        return self._headers.items()

    def __getitem__(self, key):
        return self._headers[key.lower()]

    def __contains__(self, key):
        return key.lower() in self._headers


class DummyRequest:
    """Mock FastAPI request for testing."""

    def __init__(self, path='/', query='', headers=None, client_host='127.0.0.1', method='GET', body_data=b''):
        self.url = type('u', (), {
            'path': path,
            'query': query,
            'scheme': 'http'
        })()
        self.headers = DummyHeaders(headers)
        self.client = type('c', (), {'host': client_host})()
        self.method = method
        self._body = body_data

    async def body(self):
        return self._body


@pytest.fixture
def dummy_request():
    """Provide DummyRequest class for tests."""
    return DummyRequest


@pytest.fixture
def test_client():
    """FastAPI test client with mocked upstream."""
    return TestClient(app)


@pytest.fixture
def mock_upstream_response():
    """Mock httpx.Response from upstream."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.headers = {'content-type': 'application/json'}

    async def mock_aiter_bytes(chunk_size=8192):
        yield b'{"status": "ok"}'

    mock_response.aiter_bytes = mock_aiter_bytes
    return mock_response


@pytest.fixture
def mock_httpx_client(mock_upstream_response):
    """Mock httpx.AsyncClient."""
    async_client = AsyncMock()
    async_client.request = AsyncMock(return_value=mock_upstream_response)
    async_client.aclose = AsyncMock()
    return async_client
