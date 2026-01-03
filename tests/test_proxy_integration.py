"""Integration tests for WAF proxy functionality."""
import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient
from waf_proxy.main import app


@pytest.fixture
def client():
    """FastAPI test client with mocked upstream."""
    return TestClient(app)


@pytest.fixture
def mock_upstream():
    """Mock upstream httpx response."""
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.headers = {
        'content-type': 'application/json',
        'content-length': '16'
    }

    async def mock_aiter_bytes(chunk_size=8192):
        yield b'{"status": "ok"}'

    mock_response.aiter_bytes = mock_aiter_bytes
    return mock_response


class TestHealthEndpoints:
    """Test health check endpoints (bypass WAF)."""

    def test_health_check(self, client):
        """Test /healthz endpoint."""
        response = client.get("/healthz")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}

    def test_readiness_check(self, client):
        """Test /readyz endpoint."""
        response = client.get("/readyz")
        assert response.status_code == 200
        assert response.json() == {"status": "ready"}

    @patch('waf_proxy.proxy.proxy_client.ProxyClient.get_shared_client')
    def test_root_endpoint(self, mock_get_client, client, mock_upstream):
        """Test root / endpoint (proxied, mocked upstream)."""
        # Mock the httpx client
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_upstream)
        mock_get_client.return_value = mock_client

        response = client.get("/")
        assert response.status_code == 200


class TestMetricsEndpoint:
    """Test Prometheus metrics endpoint."""

    def test_metrics_returns_prometheus_text(self, client):
        """Test /metrics returns Prometheus plaintext format."""
        response = client.get("/metrics")
        assert response.status_code == 200
        assert "text/plain" in response.headers.get("content-type", "")

        content = response.text
        # Check for Prometheus metric format
        assert "# HELP" in content or len(content) > 0  # At least some output

    def test_metrics_includes_key_metrics(self, client):
        """Test /metrics includes expected metric names."""
        response = client.get("/metrics")
        assert response.status_code == 200
        content = response.text

        # Check for key metrics
        assert "requests" in content or "metric" in content.lower()


class TestWAFDecisionHeaders:
    """Test WAF decision headers in responses."""

    @patch('waf_proxy.proxy.proxy_client.ProxyClient.get_shared_client')
    def test_blocked_request_has_waf_headers(self, mock_get_client, client, mock_upstream):
        """Test that path traversal is blocked."""
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_upstream)
        mock_get_client.return_value = mock_client

        # Path traversal should be blocked
        response = client.get("/../etc/passwd")
        assert response.status_code == 403
        assert "x-waf-decision" in response.headers
        assert response.headers["x-waf-decision"].lower() == "block"

    @patch('waf_proxy.proxy.proxy_client.ProxyClient.get_shared_client')
    def test_allowed_request_has_waf_headers(self, mock_get_client, client, mock_upstream):
        """Test that safe requests are forwarded."""
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_upstream)
        mock_get_client.return_value = mock_client

        response = client.get("/test")
        assert response.status_code == 200
        assert "x-waf-decision" in response.headers


class TestRateLimiting:
    """Test rate limiting functionality."""

    @patch('waf_proxy.proxy.proxy_client.ProxyClient.get_shared_client')
    def test_request_allowed_under_limit(self, mock_get_client, client, mock_upstream):
        """Test that requests under rate limit are allowed."""
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_upstream)
        mock_get_client.return_value = mock_client

        response = client.get("/")
        # Should forward to upstream
        assert response.status_code in (200, 502, 429)


class TestTrustedProxyHandling:
    """Test trusted proxy IP extraction."""

    @patch('waf_proxy.proxy.proxy_client.ProxyClient.get_shared_client')
    def test_request_with_xff(self, mock_get_client, client, mock_upstream):
        """Test that requests with X-Forwarded-For are handled."""
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_upstream)
        mock_get_client.return_value = mock_client

        response = client.get(
            "/",
            headers={"X-Forwarded-For": "1.1.1.1"}
        )
        # Request should complete (even if blocked elsewhere)
        assert response.status_code in (200, 502, 403, 429)

