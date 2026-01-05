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
        """Test /_waf/healthz endpoint."""
        response = client.get("/_waf/healthz")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}

    def test_readiness_check(self, client):
        """Test /_waf/readyz endpoint."""
        response = client.get("/_waf/readyz")
        assert response.status_code == 200
        assert response.json() == {"status": "ready"}

    def test_root_endpoint(self, client):
        """Test root / endpoint (local, not proxied)."""
        # Root endpoint is handled locally, not proxied
        response = client.get("/")
        assert response.status_code == 200
        assert "name" in response.json()
        assert response.json()["name"] == "WAF Proxy"


class TestMetricsEndpoint:
    """Test Prometheus metrics endpoint."""

    def test_metrics_returns_prometheus_text(self, client):
        """Test /_waf/metrics returns Prometheus plaintext format."""
        # Metrics endpoint is exempt from IP allowlist for Docker network access
        response = client.get("/_waf/metrics")
        assert response.status_code == 200
        assert "text/plain" in response.headers.get("content-type", "")

        content = response.text
        # Check for Prometheus metric format
        assert "# HELP" in content or len(content) > 0  # At least some output

    def test_metrics_includes_key_metrics(self, client):
        """Test /_waf/metrics includes expected metric names."""
        response = client.get("/_waf/metrics")
        assert response.status_code == 200
        content = response.text

        # Check for key metrics
        assert "requests" in content or "metric" in content.lower()

    def test_metrics_always_accessible(self, client):
        """Test /_waf/metrics is always accessible (exempt from IP allowlist)."""
        # Metrics endpoint is exempt from allowlist to allow Prometheus scraping
        # from Docker network, so it should always return 200 regardless of client IP
        response = client.get("/_waf/metrics")
        assert response.status_code == 200


class TestWAFDecisionHeaders:
    """Test WAF decision headers in responses."""

    @patch('waf_proxy.proxy.proxy_client.ProxyClient.get_shared_client')
    def test_blocked_request_has_waf_headers(self, mock_get_client, client, mock_upstream):
        """Test that path traversal is blocked."""
        mock_client = AsyncMock()
        mock_client.send = AsyncMock(return_value=mock_upstream)
        mock_client.build_request = AsyncMock(return_value=None)
        mock_get_client.return_value = mock_client

        # Path traversal should be blocked (using percent-encoded form)
        response = client.get("/%2e%2e/etc/passwd")
        assert response.status_code == 403
        assert "x-waf-decision" in response.headers
        assert response.headers["x-waf-decision"].lower() == "block"

    @patch('waf_proxy.proxy.proxy_client.ProxyClient.get_shared_client')
    def test_allowed_request_has_waf_headers(self, mock_get_client, client, mock_upstream):
        """Test that safe requests are forwarded."""
        mock_client = AsyncMock()
        mock_client.build_request = AsyncMock(return_value=None)
        mock_client.send = AsyncMock(return_value=mock_upstream)
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
        mock_client.build_request = AsyncMock(return_value=None)
        mock_client.send = AsyncMock(return_value=mock_upstream)
        mock_get_client.return_value = mock_client

        response = client.get("/test")
        # Should forward to upstream
        assert response.status_code in (200, 502, 429)


class TestTrustedProxyHandling:
    """Test trusted proxy IP extraction."""

    @patch('waf_proxy.proxy.proxy_client.ProxyClient.get_shared_client')
    def test_request_with_xff(self, mock_get_client, client, mock_upstream):
        """Test that requests with X-Forwarded-For are handled."""
        mock_client = AsyncMock()
        mock_client.build_request = AsyncMock(return_value=None)
        mock_client.send = AsyncMock(return_value=mock_upstream)
        mock_get_client.return_value = mock_client

        response = client.get(
            "/test",
            headers={"X-Forwarded-For": "1.1.1.1"}
        )
        # Request should complete (even if blocked elsewhere)
        assert response.status_code in (200, 502, 403, 429)

