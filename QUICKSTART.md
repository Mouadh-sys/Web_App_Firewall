# Quick Start Guide - WAF Proxy

## 5-Minute Setup

### Prerequisites
- Python 3.11+ or Docker
- curl (for testing)

### Option 1: Local Python Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the WAF
python -m waf_proxy.main

# Application starts on http://localhost:8000
```

### Option 2: Docker Setup

```bash
# 1. Build and run with docker-compose
docker-compose up --build

# 2. Wait for both services to start
# - waf_proxy on http://localhost:8000
# - demo_upstream on http://localhost:8080
```

## Testing the WAF

### Health Check

```bash
curl http://localhost:8000/healthz
# Response: {"status": "healthy"}
```

### Metrics

```bash
curl http://localhost:8000/metrics
# Response: Prometheus plaintext metrics
```

### Safe Request (Allowed)

```bash
curl http://localhost:8000/test
# Response: Proxied to upstream
# Headers: X-WAF-Decision: ALLOW
```

### Malicious Request (Blocked)

```bash
curl "http://localhost:8000/../etc/passwd"
# Response: HTTP 403 Forbidden
# Headers: X-WAF-Decision: BLOCK, X-WAF-Score: 10
```

### SQL Injection Attempt (Blocked)

```bash
curl "http://localhost:8000/?id=1' OR 1=1--"
# Response: HTTP 403 Forbidden
# Headers: X-WAF-Score: 8+
```

## Configuration

Edit `configs/example.yaml`:

```yaml
# Add upstream services
upstreams:
  - name: backend
    url: http://backend:8000
    weight: 1

# Set security thresholds
thresholds:
  allow: 5        # Score <= 5: allow
  challenge: 6    # Score 6-9: allow but mark
  block: 10       # Score >= 10: block

# Configure rate limiting (per IP)
rate_limits:
  requests_per_minute: 60

# Trusted proxies (for X-Forwarded-For)
trusted_proxies:
  - 10.0.0.0/8

# WAF behavior
waf_settings:
  mode: block     # or "monitor" (never block)
```

## Key Features

✅ **Rate Limiting**: HTTP 429 after 60 requests/minute per IP
✅ **Path Traversal Detection**: Blocks `/../`, `%2e%2e/`
✅ **SQL Injection Detection**: Blocks `UNION SELECT`, `OR 1=1`, etc.
✅ **XSS Prevention**: Blocks script tags, event handlers
✅ **Prometheus Metrics**: `/metrics` endpoint for monitoring
✅ **Request Tracing**: X-Request-ID header on all responses
✅ **Trusted Proxies**: Safe X-Forwarded-For extraction

## Monitoring

### View Current Metrics

```bash
curl -s http://localhost:8000/metrics | grep requests_total
# Shows: requests_total{verdict="ALLOW",status="200"} 42
```

### Common Metrics

- `requests_total`: Total requests by verdict and status
- `waf_rule_hits_total`: Rule hits by rule ID
- `rate_limited_requests_total`: Requests blocked by rate limiter
- `upstream_latency_seconds`: Upstream response time histogram
- `upstream_errors_total`: Failed upstream connections

## Logs

Logs are JSON-formatted to stdout:

```json
{
  "level": "INFO",
  "message": "[abc123] Request: 192.168.1.1 GET /api/users",
  "timestamp": "2026-01-03 12:34:56,789",
  "request_id": "abc123",
  "client_ip": "192.168.1.1",
  "method": "GET",
  "path": "/api/users",
  "verdict": "ALLOW",
  "score": 0,
  "status": 200,
  "latency_ms": 45.2
}
```

## Deployment

### Single Instance

```bash
# Build image
docker build -t waf-proxy .

# Run with custom config
docker run -p 8000:8000 \
  -e CONFIG_PATH=/config/custom.yaml \
  -v $(pwd)/configs:/config \
  waf-proxy
```

### Multiple Instances

For horizontal scaling:

1. Use Docker Swarm or Kubernetes
2. Add Redis for distributed rate limiting
3. Use Prometheus Pushgateway for metrics aggregation
4. Add load balancer in front

## Troubleshooting

### No response from upstream

Check that upstream is reachable:
```bash
curl http://backend:8000/health
```

Update `configs/example.yaml` with correct upstream URL.

### Rate limit too strict

Increase `requests_per_minute`:
```yaml
rate_limits:
  requests_per_minute: 1000
```

### False positives (legitimate traffic blocked)

Switch to monitor mode (doesn't block):
```yaml
waf_settings:
  mode: monitor
```

Review blocked requests and adjust rules.

### Metrics not working

Verify metrics endpoint:
```bash
curl http://localhost:8000/metrics
```

Check Prometheus format: should have `# HELP` comments.

## Architecture

```
Client
  ↓
WAF Proxy (FastAPI)
  ├─ Rate Limiter (per-IP)
  ├─ Security Engine (rule evaluation)
  └─ Proxy Client (upstream forwarding)
      └─ Upstream Service(s)
```

## Next Steps

1. Read [IMPLEMENTATION.md](IMPLEMENTATION.md) for detailed changes
2. Review [CHANGELOG.md](CHANGELOG.md) for complete feature list
3. Check [README.md](README.md) for production setup
4. Run `pytest -q` to verify tests
5. Set up Prometheus scraping of `/metrics`

---

For support or issues, check the README.md or CHANGELOG.md files.

