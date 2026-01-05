"""WAF Proxy FastAPI application."""
import asyncio
import os
import logging
import httpx
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException
from starlette.responses import Response
from waf_proxy.config import load_config
from waf_proxy.models import Config
from waf_proxy.middleware.waf_middleware import WAFMiddleware
from waf_proxy.observability.logging import setup_logging
from waf_proxy.observability.metrics import get_metrics_text
from waf_proxy.proxy.proxy_client import ProxyClient
from waf_proxy.proxy.rate_limiter import RateLimiter
from waf_proxy.waf.normalize import get_client_ip

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)

# Load initial configuration
config = load_config()

cleanup_task: asyncio.Task = None
config_poll_task: asyncio.Task = None


async def cleanup_rate_limiter_periodically(rate_limiter: RateLimiter, interval_seconds: int = 60):
    """Background task to periodically cleanup expired rate limiter buckets."""
    try:
        while True:
            await asyncio.sleep(interval_seconds)
            await rate_limiter.cleanup_old_buckets(ttl_seconds=3600.0)
    except asyncio.CancelledError:
        logger.info("Rate limiter cleanup task cancelled")
        raise


async def poll_control_plane_config(
    control_plane_url: str,
    control_plane_token: str,
    poll_interval_seconds: int,
    middleware: WAFMiddleware
):
    """
    Poll control plane for config updates and reload atomically.
    
    Args:
        control_plane_url: URL to fetch config from
        control_plane_token: Bearer token for authentication
        poll_interval_seconds: Polling interval
        middleware: WAFMiddleware instance to reload
    """
    last_etag = None
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            while True:
                try:
                    headers = {
                        'Authorization': f'Bearer {control_plane_token}'
                    }
                    if last_etag:
                        headers['If-None-Match'] = last_etag
                    
                    response = await client.get(control_plane_url, headers=headers)
                    
                    if response.status_code == 304:
                        # No change
                        logger.debug("Config unchanged (304)")
                    elif response.status_code == 200:
                        # New config available
                        config_data = response.json()
                        etag = response.headers.get('ETag', '').strip('"')
                        
                        # Validate and parse config
                        try:
                            new_config = Config(**config_data)
                            
                            # Reload middleware config atomically
                            await middleware.reload_config(new_config, version_hash=etag)
                            last_etag = etag
                            logger.info(f"Config reloaded from control plane (ETag: {etag})")
                        except Exception as e:
                            logger.error(f"Failed to parse/validate config from control plane: {e}", exc_info=True)
                    elif response.status_code == 401:
                        logger.warning("Control plane authentication failed")
                    elif response.status_code == 404:
                        logger.warning("No active config in control plane")
                    else:
                        logger.warning(f"Control plane returned status {response.status_code}")
                        
                except httpx.TimeoutException:
                    logger.warning("Control plane request timed out")
                except httpx.RequestError as e:
                    logger.warning(f"Control plane request failed: {e}")
                except Exception as e:
                    logger.error(f"Unexpected error polling control plane: {e}", exc_info=True)
                
                await asyncio.sleep(poll_interval_seconds)
                
        except asyncio.CancelledError:
            logger.info("Config polling task cancelled")
            raise


# Lifecycle management
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manage application lifecycle.

    Startup: Initialize
    Shutdown: Cleanup resources
    """
    global cleanup_task, config_poll_task
    
    logger.info("WAF Proxy starting up")
    
    # Schedule cleanup task (middleware has already initialized rate limiter)
    rate_limiter = getattr(app.state, 'rate_limiter', None)
    if rate_limiter:
        cleanup_task = asyncio.create_task(cleanup_rate_limiter_periodically(rate_limiter, 60))
        logger.info("Rate limiter cleanup task scheduled")
    
    # Schedule config polling if control plane URL is configured
    control_plane_url = os.environ.get('CONTROL_PLANE_URL')
    control_plane_token = os.environ.get('CONTROL_PLANE_TOKEN')
    poll_interval = int(os.environ.get('CONTROL_PLANE_POLL_SECONDS', '10'))
    
    if control_plane_url and control_plane_token:
        # Get middleware from app.state (set during middleware initialization)
        # In Starlette/FastAPI, middleware __init__ is called when add_middleware is called,
        # so app.state.waf_middleware should be available here
        middleware = getattr(app.state, 'waf_middleware', None)
        if middleware:
            config_poll_task = asyncio.create_task(
                poll_control_plane_config(control_plane_url, control_plane_token, poll_interval, middleware)
            )
            logger.info(f"Config polling task scheduled (interval: {poll_interval}s, URL: {control_plane_url})")
        else:
            # This shouldn't happen if middleware is properly initialized
            # But if it does, we'll try to get it after a short delay
            logger.warning("Middleware not found in app.state, will retry after brief delay")
            async def delayed_poll_start():
                await asyncio.sleep(0.1)  # Brief delay to allow middleware init
                middleware = getattr(app.state, 'waf_middleware', None)
                if middleware:
                    asyncio.create_task(
                        poll_control_plane_config(control_plane_url, control_plane_token, poll_interval, middleware)
                    )
                    logger.info(f"Config polling task started (delayed, interval: {poll_interval}s)")
                else:
                    logger.error("Failed to start config polling: middleware not found")
            asyncio.create_task(delayed_poll_start())
    else:
        logger.info("Control plane polling disabled (CONTROL_PLANE_URL or CONTROL_PLANE_TOKEN not set)")
    
    yield
    
    logger.info("WAF Proxy shutting down")
    
    # Cancel tasks
    if cleanup_task:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass
    
    if config_poll_task:
        config_poll_task.cancel()
        try:
            await config_poll_task
        except asyncio.CancelledError:
            pass
    
    await ProxyClient.close_shared_client()


# Create FastAPI app
app = FastAPI(title="WAF Proxy", version="1.0.0", lifespan=lifespan)

# Add WAF middleware
app.add_middleware(WAFMiddleware, config=config)


# Internal endpoints under /_waf/* reserved prefix (bypass WAF, avoid conflicts with upstream)
@app.get("/_waf/healthz")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.get("/_waf/readyz")
async def readiness_check():
    """Readiness probe."""
    return {"status": "ready"}


# Metrics endpoint (Prometheus plaintext format) - exempt from allowlist for Docker network access
@app.get("/_waf/metrics")
async def metrics(request: Request):
    """
    Prometheus metrics endpoint.
    Exempt from IP allowlist check to allow Prometheus scraping from Docker network.

    Returns:
        Prometheus plaintext format metrics
    """
    # Note: We exempt /_waf/metrics from allowlist check to allow Prometheus
    # scraping from Docker network. In production, consider adding network-level
    # restrictions or authentication.
    metrics_data = get_metrics_text()
    return Response(content=metrics_data, media_type="text/plain; version=0.0.4")


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": "WAF Proxy",
        "version": "1.0.0",
        "docs": "/docs",
        "metrics": "/_waf/metrics",
        "health": "/_waf/healthz",
        "ready": "/_waf/readyz"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_config=None  # Use our JSON logging
    )

