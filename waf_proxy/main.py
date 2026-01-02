from fastapi import FastAPI, Request
from starlette.responses import JSONResponse
from waf_proxy.middleware.waf_middleware import WAFMiddleware
from waf_proxy.config import load_config
from waf_proxy.observability.logging import setup_logging
from waf_proxy.observability.metrics import record_request

app = FastAPI()

# Load configuration
config = load_config("configs/example.yaml")

# Add WAF middleware
app.add_middleware(WAFMiddleware, config=config)

# Setup logging
setup_logging()

@app.get("/metrics")
async def metrics():
    return JSONResponse(content={"metrics": "not implemented"})
    # Placeholder for Prometheus metrics

@app.get("/readyz")
async def readiness_check():
    return {"status": "healthy"}

@app.get("/healthz")
async def health_check():
    return {"status": "healthy"}

@app.middleware("http")
async def waf_middleware(request: Request, call_next):
    response = await call_next(request)
    # Placeholder for WAF logic
    return response

@app.middleware("http")
async def observability_middleware(request: Request, call_next):
    response = await call_next(request)
    record_request(verdict="ALLOW", status=response.status_code)  # Example usage
    return response
