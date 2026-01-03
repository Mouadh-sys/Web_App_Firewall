# Mini WAF Reverse Proxy

This project implements a Web Application Firewall (WAF) reverse proxy using FastAPI. It is designed to inspect and filter incoming requests before forwarding them to upstream services.

## Features
- **Routing/Proxy Layer**: Forwards requests to upstream services with support for host/path-based routing.
- **Security Engine**: Detects malicious patterns and applies anomaly scoring.
- **Decision Layer**: Allows, blocks, or marks requests as suspicious based on security rules.
- **Observability**: Structured JSON logging and simple metrics.
- **Configuration**: YAML-based configuration with environment variable overrides.

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

### New WAF behavior
- The WAF now normalizes request path/query/selected headers and applies rules to multiple targets (path, query, headers).
- IP allowlist and blocklist are supported in `configs/example.yaml`.
- Decision logic:
  - score >= 10 => BLOCK (HTTP 403)
  - score 6..9 => ALLOW but marked SUSPICIOUS (request still forwarded)
  - score <= 5 => ALLOW
- Response headers added to all responses (including BLOCK):
  - `X-WAF-Decision`: ALLOW | SUSPICIOUS | BLOCK
  - `X-WAF-Score`: total numeric score

### Example requests (using curl)

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
