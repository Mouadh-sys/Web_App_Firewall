"""WAF Proxy FastAPI application."""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from starlette.responses import Response
from waf_proxy.config import load_config
from waf_proxy.middleware.waf_middleware import WAFMiddleware
from waf_proxy.observability.logging import setup_logging
from waf_proxy.observability.metrics import get_metrics_text
from waf_proxy.proxy.proxy_client import ProxyClient

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)

# Load configuration
config = load_config()

# Lifecycle management
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manage application lifecycle.

    Startup: Initialize
    Shutdown: Cleanup resources
    """
    logger.info("WAF Proxy starting up")
    yield
    logger.info("WAF Proxy shutting down")
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

