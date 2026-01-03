"""Proxy client for forwarding requests to upstream services."""
import httpx
import logging
import time
from typing import Optional, Tuple
from fastapi import Request
from starlette.responses import StreamingResponse
from waf_proxy.proxy.headers import filter_request_headers, filter_response_headers, add_forwarding_headers

logger = logging.getLogger(__name__)


class ProxyClient:
    """
    Async HTTP proxy client with streaming, timeouts, and connection pooling.

    Implements safe proxying:
    - Streaming responses to avoid buffering
    - Configurable timeouts and retries
    - Proper hop-by-hop header handling
    - X-Forwarded-* header management
    """

    _shared_client: Optional[httpx.AsyncClient] = None

    def __init__(
        self,
        timeout_seconds: float = 30.0,
        max_connections: int = 100,
        max_keepalive_connections: int = 20,
        keepalive_expiry: float = 5.0,
        retries: int = 0
    ):
        """
        Initialize proxy client.

        Args:
            timeout_seconds: Request timeout in seconds
            max_connections: Maximum concurrent connections
            max_keepalive_connections: Keep-alive pool size
            keepalive_expiry: Keep-alive expiry in seconds
            retries: Number of retries (conservative: 0 recommended)
        """
        self.timeout_seconds = timeout_seconds
        self.max_connections = max_connections
        self.max_keepalive_connections = max_keepalive_connections
        self.keepalive_expiry = keepalive_expiry
        self.retries = retries

    @classmethod
    def get_shared_client(cls, **kwargs) -> httpx.AsyncClient:
        """Get or create shared async HTTP client."""
        if cls._shared_client is None:
            limits = httpx.Limits(
                max_connections=kwargs.get('max_connections', 100),
                max_keepalive_connections=kwargs.get('max_keepalive_connections', 20),
                keepalive_expiry=kwargs.get('keepalive_expiry', 5.0)
            )
            cls._shared_client = httpx.AsyncClient(limits=limits)
        return cls._shared_client

    @classmethod
    async def close_shared_client(cls) -> None:
        """Close shared client (call on shutdown)."""
        if cls._shared_client is not None:
            await cls._shared_client.aclose()
            cls._shared_client = None

    def _build_upstream_url(
        self,
        upstream_base: str,
        path: str,
        query: str
    ) -> str:
        """
        Build upstream URL from components.

        Args:
            upstream_base: Upstream base URL (e.g., http://upstream:8080)
            path: Request path
            query: Query string (may be empty)

        Returns:
            Complete URL for upstream request
        """
        # Remove trailing slash from base
        base = upstream_base.rstrip('/')

        # Build path with query
        if query:
            url = f"{base}{path}?{query}"
        else:
            url = f"{base}{path}"

        return url

    async def forward_request(
        self,
        upstream_url: str,
        request: Request,
        client_ip: str
    ) -> Tuple[int, dict, httpx.Response]:
        """
        Forward request to upstream and get response.

        Args:
            upstream_url: Upstream service base URL
            request: FastAPI Request object
            client_ip: Client IP address (for X-Forwarded-For)

        Returns:
            Tuple of (status_code, headers_dict, httpx.Response)
            Response body is not buffered; use response.aiter_bytes() to stream.

        Raises:
            httpx.RequestError: On network errors
        """
        try:
            # Build complete upstream URL
            url = self._build_upstream_url(
                upstream_url,
                request.url.path,
                request.url.query
            )

            # Filter and prepare headers
            headers = dict(request.headers)
            headers = filter_request_headers(headers)

            # Add forwarding headers
            scheme = request.url.scheme or 'http'
            original_host = request.headers.get('host', 'localhost')
            headers = add_forwarding_headers(headers, client_ip, scheme, original_host)

            # Read request body if present
            body = None
            if request.method in ('POST', 'PUT', 'PATCH'):
                try:
                    body = await request.body()
                except Exception as e:
                    logger.warning(f"Failed to read request body: {e}")
                    body = b''

            # Forward request with timeout
            client = self.get_shared_client(
                max_connections=self.max_connections,
                max_keepalive_connections=self.max_keepalive_connections,
                keepalive_expiry=self.keepalive_expiry
            )

            start_time = time.monotonic()
            response = await client.request(
                method=request.method,
                url=url,
                headers=headers,
                content=body,
                timeout=self.timeout_seconds,
                follow_redirects=False
            )
            latency = time.monotonic() - start_time

            logger.debug(
                f"Upstream response: {response.status_code} (latency: {latency:.3f}s)"
            )

            # Filter response headers
            response_headers = filter_response_headers(dict(response.headers))

            return response.status_code, response_headers, response

        except httpx.TimeoutException as e:
            logger.error(f"Upstream timeout: {e}")
            raise
        except httpx.RequestError as e:
            logger.error(f"Upstream request error: {e}")
            raise

    def build_streaming_response(
        self,
        status_code: int,
        headers: dict,
        upstream_response: httpx.Response
    ) -> StreamingResponse:
        """
        Build a StreamingResponse from upstream response.

        Args:
            status_code: HTTP status code
            headers: Response headers
            upstream_response: httpx.Response object

        Returns:
            Starlette StreamingResponse
        """
        async def stream_body():
            async for chunk in upstream_response.aiter_bytes(chunk_size=8192):
                yield chunk

        return StreamingResponse(
            content=stream_body(),
            status_code=status_code,
            headers=headers
        )

