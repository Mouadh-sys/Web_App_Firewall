# Mini WAF Reverse Proxy

This project implements a Web Application Firewall (WAF) reverse proxy using FastAPI. It is designed to inspect and filter incoming requests before forwarding them to upstream services.

## Features
- **Routing/Proxy Layer**: Forwards requests to upstream services with support for host/path-based routing
- **Security Engine**: Detects malicious patterns and applies anomaly scoring with configurable thresholds
- **Rate Limiting**: Token bucket-based per-IP rate limiting (requests per minute, async-safe)
- **Trusted Proxy Support**: Safe X-Forwarded-For extraction (CIDR-based trust list)
- **Streaming Responses**: Avoids buffering upstream responses; supports streaming to clients
- **Proper Header Handling**: Strips hop-by-hop headers, adds X-Forwarded-* headers correctly
- **Observability**: JSON structured logging + Prometheus metrics (/metrics endpoint)
- **Configuration**: YAML-based with environment variable overrides (CONFIG_PATH)
- **Docker**: Production-ready Dockerfile with health checks and non-root user

## Security Highlights

### Client IP Extraction (Trusted Proxies)
- Respects `trusted_proxies` CIDR list in config
- Only uses X-Forwarded-For if peer IP is in trusted list (prevents spoofing)
- Falls back to peer IP if untrusted

### Rate Limiting
- Token bucket algorithm per client IP
- Configurable requests_per_minute (default 60)
- Returns HTTP 429 when limit exceeded
- In-memory storage (Redis recommended for multi-instance)

## Quickstart

### Prerequisites
- Python 3.11+
- Docker and Docker Compose

### Setup
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd Web_Application_Firewall
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application locally:
   ```bash
   uvicorn waf_proxy.main:app --reload
   ```

4. Run with Docker Compose (local demo upstream will be available):
   ```bash
   docker-compose up
   ```

### Configuration (configs/example.yaml)

Key configuration sections:

```yaml
upstreams:
  - name: demo_upstream
    url: http://demo_upstream:8080
    weight: 1
    # Optional: restrict to hosts or path prefixes
    # hosts: [example.com, www.example.com]
    # path_prefixes: [/api/, /admin/]

# IP-based fast-path decisions
ip_allowlist: [127.0.0.1, ::1]
ip_blocklist: []

# Trusted proxies for X-Forwarded-For (CIDR ranges)
trusted_proxies:
  - 127.0.0.1
  - ::1
  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16

# WAF thresholds
thresholds:
  allow: 5           # Score <= 5: allow
  challenge: 6       # Score 6-9: allow but mark suspicious
  block: 10          # Score >= 10: block (HTTP 403)

# Rate limiting
rate_limits:
  requests_per_minute: 60  # Default per IP

# Proxy client settings
proxy_settings:
  timeout_seconds: 30.0
  max_connections: 100
  max_keepalive_connections: 20

# WAF engine settings
waf_settings:
  mode: "block"      # "block" or "monitor" (monitor = never block, only log)
  max_inspect_bytes: 10000
  inspect_body: false
```

### Environment Variables

- `CONFIG_PATH`: Path to YAML config (default: `configs/example.yaml`)

### Example Requests

1) Allowed request (forwards to demo upstream):

```bash
curl -i http://127.0.0.1:8000/hello/test
# Response will include headers: X-WAF-Decision: ALLOW and X-WAF-Score: 0
```

2) Blocked path traversal (returns 403 JSON):

```bash
curl -i http://127.0.0.1:8000/../etc/passwd
# Response: 403 and JSON {"blocked": true, "reason": "waf", "score": 10, "rule_ids": ["PT001"]}
# Headers include X-WAF-Decision: BLOCK and X-WAF-Score: 10
```

3) Suspicious request (still forwarded) example:

```bash
curl -i -H "User-Agent: sqlmap" "http://127.0.0.1:8000/search?q=test"
# Should be forwarded; response includes X-WAF-Decision: SUSPICIOUS and X-WAF-Score: 6
```

### Configuration
- Edit `configs/example.yaml` to change rules, allowlist/blocklist and upstreams. Default rules include PT001, SQLI001, XSS001, SSRF001, UA001.

### Tests
Run unit tests with:

```bash
pytest -q
```

## Project Structure
```text
repo/
  README.md
  pyproject.toml
  waf_proxy/
    main.py                  # FastAPI app entrypoint
    config.py                # Config load + models
    middleware/
      request_context.py     # Normalize request into context
      waf_middleware.py      # Calls security engine + decision
    proxy/
      router.py              # Host/path routing + LB
      proxy_client.py        # HTTPX forwarding
      headers.py             # Hop-by-hop handling
    waf/
      engine.py              # Evaluate + score + decide hooks
      rules.py               # Rule loading + matching
      rate_limit.py          # Token bucket + stores
      detectors.py           # ML stub + interface
    observability/
      logging.py             # JSON logger setup
      metrics.py             # Prometheus metrics
  configs/
    example.yaml
  demo_upstream/
    app.py                   # Tiny upstream FastAPI/Flask app
  tests/
    test_rules.py
    test_rate_limit.py
    test_decision.py
    test_proxy_integration.py
  docker-compose.yml
  Dockerfile
```

## License
[MIT License](LICENSE)
