"""WAF Proxy FastAPI application."""
import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from starlette.responses import Response
from waf_proxy.config import load_config
from waf_proxy.middleware.waf_middleware import WAFMiddleware
from waf_proxy.observability.logging import setup_logging
from waf_proxy.observability.metrics import get_metrics_text
from waf_proxy.proxy.proxy_client import ProxyClient
from waf_proxy.proxy.rate_limiter import RateLimiter

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)

# Load configuration
config = load_config()

cleanup_task: asyncio.Task = None


async def cleanup_rate_limiter_periodically(rate_limiter: RateLimiter, interval_seconds: int = 60):
    """Background task to periodically cleanup expired rate limiter buckets."""
    try:
        while True:
            await asyncio.sleep(interval_seconds)
            await rate_limiter.cleanup_old_buckets(ttl_seconds=3600.0)
    except asyncio.CancelledError:
        logger.info("Rate limiter cleanup task cancelled")
        raise


# Lifecycle management
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manage application lifecycle.

    Startup: Initialize
    Shutdown: Cleanup resources
    """
    global cleanup_task
    
    logger.info("WAF Proxy starting up")
    
    # Schedule cleanup task (middleware has already initialized rate limiter)
    rate_limiter = getattr(app.state, 'rate_limiter', None)
    if rate_limiter:
        cleanup_task = asyncio.create_task(cleanup_rate_limiter_periodically(rate_limiter, 60))
        logger.info("Rate limiter cleanup task scheduled")
    
    yield
    
    logger.info("WAF Proxy shutting down")
    
    # Cancel cleanup task
    if cleanup_task:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass
    
    await ProxyClient.close_shared_client()


# Create FastAPI app
app = FastAPI(title="WAF Proxy", version="1.0.0", lifespan=lifespan)

# Add WAF middleware
app.add_middleware(WAFMiddleware, config=config)


# Health check endpoints (fast, bypass WAF via internal paths)
@app.get("/healthz")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.get("/readyz")
async def readiness_check():
    """Readiness probe."""
    return {"status": "ready"}


# Metrics endpoint (Prometheus plaintext format)
@app.get("/metrics")
async def metrics():
    """
    Prometheus metrics endpoint.

    Returns:
        Prometheus plaintext format metrics
    """
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
        "metrics": "/metrics",
        "health": "/healthz",
        "ready": "/readyz"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_config=None  # Use our JSON logging
    )

