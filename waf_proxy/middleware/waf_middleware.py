"""WAF middleware for request inspection and decision-making."""
import uuid
import time
import logging
from fastapi import Request
from starlette.responses import JSONResponse
from waf_proxy.waf.engine import SecurityEngine
from waf_proxy.proxy.proxy_client import ProxyClient
from waf_proxy.proxy.router import Router
from waf_proxy.proxy.rate_limiter import RateLimiter
from waf_proxy.waf.normalize import build_inspection_dict, get_client_ip
from waf_proxy.observability.metrics import (
    record_request, record_rate_limit, record_upstream_latency, record_upstream_error
)

logger = logging.getLogger(__name__)

# Internal endpoints that bypass WAF
INTERNAL_PATHS = {'/metrics', '/readyz', '/healthz', '/docs', '/redoc', '/openapi.json'}


def _to_dict(obj):
    """Convert Pydantic model to dict if needed."""
    if hasattr(obj, 'model_dump'):
        return obj.model_dump()
    elif hasattr(obj, 'dict'):
        return obj.dict()
    return obj


class WAFMiddleware:
    """
    ASGI middleware that:
    1. Inspects requests against WAF rules
    2. Makes verdict decisions (ALLOW/SUSPICIOUS/BLOCK)
    3. Forwards allowed/suspicious requests to upstream
    4. Enforces rate limiting
    5. Records metrics and logs
    """

    def __init__(self, app, config):
        """
        Initialize middleware.

        Args:
            app: ASGI application
            config: Pydantic Config object with upstreams, rules, rate limits, etc.
        """
        self.app = app
        self.config = config

        # WAF engine
        self.security_engine = SecurityEngine(config)

        # Router
        upstreams = config.upstreams if hasattr(config, 'upstreams') else config.get('upstreams', [])
        self.router = Router(upstreams)

        # Proxy client with settings from config
        proxy_cfg = config.proxy_settings if hasattr(config, 'proxy_settings') else (config.get('proxy_settings') or {})
        if hasattr(proxy_cfg, 'dict'):
            proxy_cfg = proxy_cfg.dict()

        self.proxy_client = ProxyClient(
            timeout_seconds=proxy_cfg.get('timeout_seconds', 30.0),
            max_connections=proxy_cfg.get('max_connections', 100),
            max_keepalive_connections=proxy_cfg.get('max_keepalive_connections', 20),
            keepalive_expiry=proxy_cfg.get('keepalive_expiry', 5.0),
            retries=proxy_cfg.get('retries', 0)
        )

        # Rate limiter
        rate_limit_cfg = config.rate_limits if hasattr(config, 'rate_limits') else (config.get('rate_limits') or {})
        if hasattr(rate_limit_cfg, 'dict'):
            rate_limit_cfg = rate_limit_cfg.dict()

        default_rpm = rate_limit_cfg.get('requests_per_minute', 60) if rate_limit_cfg else 60
        self.rate_limiter = RateLimiter(default_rpm)

        # Store rate limiter in app.state for cleanup scheduling
        if hasattr(app, 'state'):
            app.state.rate_limiter = self.rate_limiter

        # WAF settings
        waf_cfg = config.waf_settings if hasattr(config, 'waf_settings') else (config.get('waf_settings') or {})
        if hasattr(waf_cfg, 'dict'):
            waf_cfg = waf_cfg.dict()

        self.max_inspect_bytes = waf_cfg.get('max_inspect_bytes', 10000)
        self.max_body_bytes = waf_cfg.get('max_body_bytes', 1000000)
        self.inspect_body = waf_cfg.get('inspect_body', False)
        self.trusted_proxies = config.trusted_proxies if hasattr(config, 'trusted_proxies') else config.get('trusted_proxies')

    async def __call__(self, scope, receive, send):
        """
        ASGI interface.

        Args:
            scope: ASGI scope
            receive: ASGI receive
            send: ASGI send
        """
        if scope['type'] != 'http':
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)
        request_id = str(uuid.uuid4())[:8]
        start_time = time.monotonic()

        # Bypass WAF for internal endpoints
        if request.url.path in INTERNAL_PATHS:
            await self.app(scope, receive, send)
            return

        try:
            # Extract client IP with trusted proxy support
            client_ip = get_client_ip(request, self.trusted_proxies)

            # Check rate limiting BEFORE WAF evaluation
            is_allowed = await self.rate_limiter.is_allowed(
                key=client_ip,
                limit=None  # Use default from config
            )

            if not is_allowed:
                logger.warning(
                    f"[{request_id}] Rate limited: {client_ip} {request.method} {request.url.path}"
                )
                record_rate_limit(client_ip)
                response = JSONResponse(
                    content={'error': 'rate_limited', 'message': 'Too many requests'},
                    status_code=429
                )
                response.headers['X-Request-ID'] = request_id
                await response(scope, receive, send)
                return

            # Read and validate request body size
            body_bytes = None
            if request.method in ('POST', 'PUT', 'PATCH'):
                # Check Content-Length header first (fast path)
                content_length_str = request.headers.get('content-length')
                if content_length_str:
                    try:
                        content_length = int(content_length_str)
                        if content_length > self.max_body_bytes:
                            logger.warning(
                                f"[{request_id}] Request body too large: {content_length} > {self.max_body_bytes}"
                            )
                            response = JSONResponse(
                                content={'error': 'payload_too_large', 'message': 'Request body exceeds maximum size'},
                                status_code=413
                            )
                            response.headers['X-Request-ID'] = request_id
                            await response(scope, receive, send)
                            return
                    except ValueError:
                        # Invalid Content-Length, continue to read body
                        pass

                # Read body with size limit (using stream to check size incrementally)
                try:
                    body_bytes = b''
                    async for chunk in request.stream():
                        body_bytes += chunk
                        if len(body_bytes) > self.max_body_bytes:
                            logger.warning(
                                f"[{request_id}] Request body exceeds limit: {len(body_bytes)} > {self.max_body_bytes}"
                            )
                            response = JSONResponse(
                                content={'error': 'payload_too_large', 'message': 'Request body exceeds maximum size'},
                                status_code=413
                            )
                            response.headers['X-Request-ID'] = request_id
                            await response(scope, receive, send)
                            return
                except Exception as e:
                    logger.warning(f"[{request_id}] Failed to read request body: {e}")
                    body_bytes = b''

            # Build inspection context (include body if inspect_body is enabled)
            inspection = build_inspection_dict(
                request, self.max_inspect_bytes,
                body_bytes=body_bytes if self.inspect_body else None
            )

            # Evaluate against WAF rules
            result = self.security_engine.evaluate(inspection, client_ip)
            verdict = result.get('verdict')
            score = result.get('score', 0)
            findings = result.get('findings', [])
            rule_ids = result.get('rule_ids', [])

            # Log request
            logger.info(
                f"[{request_id}] Request: {client_ip} {request.method} {request.url.path}",
                extra={
                    'request_id': request_id,
                    'client_ip': client_ip,
                    'method': request.method,
                    'path': request.url.path,
                    'verdict': verdict,
                    'score': score,
                    'rule_ids': rule_ids,
                }
            )

            # Prepare WAF response headers
            waf_headers = {
                'X-WAF-Decision': verdict,
                'X-WAF-Score': str(score),
                'X-Request-ID': request_id,
            }

            # Block decision
            if verdict == 'BLOCK':
                latency_ms = (time.monotonic() - start_time) * 1000
                record_request(verdict=verdict, status=403)

                logger.warning(
                    f"[{request_id}] Blocked: score={score} rules={rule_ids}",
                    extra={
                        'request_id': request_id,
                        'verdict': verdict,
                        'score': score,
                        'rule_ids': rule_ids,
                    }
                )

                response = JSONResponse(
                    content={
                        'blocked': True,
                        'reason': 'waf',
                        'score': score,
                        'rule_ids': rule_ids,
                        'request_id': request_id,
                    },
                    status_code=403
                )
                response.headers.update(waf_headers)
                await response(scope, receive, send)
                return

            # Allow or suspicious: forward to upstream
            try:
                upstream_url = self.router.get_upstream(request)

                if not upstream_url:
                    logger.error(f"[{request_id}] No upstream available")
                    response = JSONResponse(
                        content={'error': 'no_upstream', 'request_id': request_id},
                        status_code=502
                    )
                    response.headers.update(waf_headers)
                    record_request(verdict='ERROR', status=502)
                    await response(scope, receive, send)
                    return

                # Forward request to upstream (pass body_bytes if we read it)
                upstream_start = time.monotonic()
                status_code, response_headers, upstream_response = await self.proxy_client.forward_request(
                    upstream_url, request, client_ip, body_bytes=body_bytes
                )
                upstream_latency = time.monotonic() - upstream_start

                # Record metrics
                record_upstream_latency(upstream_latency)
                record_request(verdict=verdict, status=status_code)

                # Add WAF headers to response
                response_headers.update(waf_headers)

                # Build streaming response
                response = self.proxy_client.build_streaming_response(
                    status_code, response_headers, upstream_response
                )

                latency_ms = (time.monotonic() - start_time) * 1000
                logger.info(
                    f"[{request_id}] Forwarded: {upstream_url} {status_code} ({latency_ms:.1f}ms)",
                    extra={
                        'request_id': request_id,
                        'upstream': upstream_url,
                        'status': status_code,
                        'latency_ms': latency_ms,
                    }
                )

                await response(scope, receive, send)

            except Exception as e:
                logger.error(
                    f"[{request_id}] Upstream error: {type(e).__name__}: {e}",
                    exc_info=True
                )
                record_upstream_error(type(e).__name__)
                record_request(verdict='ERROR', status=502)

                response = JSONResponse(
                    content={
                        'error': 'upstream_error',
                        'message': 'Failed to reach upstream',
                        'request_id': request_id,
                    },
                    status_code=502
                )
                response.headers.update(waf_headers)
                await response(scope, receive, send)

        except Exception as e:
            logger.error(
                f"[{request_id}] Middleware error: {type(e).__name__}: {e}",
                exc_info=True
            )
            response = JSONResponse(
                content={
                    'error': 'internal_error',
                    'request_id': request_id,
                },
                status_code=500
            )
            await response(scope, receive, send)


