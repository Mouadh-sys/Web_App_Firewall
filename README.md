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
- Docker and Docker Compose
- MongoDB Atlas account (for Django control plane)

### Setup

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd Web_Application_Firewall
   ```

2. **Create `.env` file from example:**
   ```bash
   cp .env.example .env
   ```

3. **Edit `.env` and set your MongoDB Atlas credentials:**
   ```bash
   MONGODB_URI=mongodb+srv://username:password@cluster0.xxxxx.mongodb.net/?retryWrites=true&w=majority
   MONGODB_NAME=waf_dashboard
   DJANGO_SECRET_KEY=your-secret-key-here
   WAF_API_TOKEN=dev-control-plane-token
   ```

   **Important:** 
   - Replace `YOUR_PASSWORD` in `MONGODB_URI` with your actual MongoDB Atlas password
   - Generate a secure `DJANGO_SECRET_KEY` (e.g., using `python -c "import secrets; print(secrets.token_urlsafe(50))"`)
   - Ensure your MongoDB Atlas IP allowlist includes your Docker host IP (or use `0.0.0.0/0` for development only)

4. **Start the stack:**
   ```bash
   docker compose up --build
   ```

5. **Create Django superuser (in another terminal):**
   ```bash
   docker compose exec django_dashboard python manage.py createsuperuser
   ```

6. **Access the services:**
   - WAF Proxy: http://localhost/
   - Django Dashboard: http://localhost/dashboard/
   - Django Admin: http://localhost/dashboard/admin/
   - Grafana: http://localhost/grafana/
   - Prometheus: http://localhost:9090 (if exposed)

### Verification

1. **Test WAF proxy:**
   ```bash
   curl http://localhost/
   # Should forward to demo upstream
   ```

2. **Test blocked request:**
   ```bash
   curl http://localhost/../etc/passwd
   # Should return 403
   ```

3. **Check Prometheus targets:**
   - Open http://localhost:9090/targets
   - Verify `waf_proxy` target is UP

4. **Test config polling:**
   - Log into Django admin at http://localhost/dashboard/admin/
   - Create/update WAF rules or policy
   - Click "Publish current config" action on Policy
   - Check WAF logs - should see config reload within poll interval (default 10s)
   - Check Prometheus metric: `waf_config_version_info`

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

**WAF Proxy:**
- `CONFIG_PATH`: Path to YAML config (default: `configs/docker.yaml`)
- `CONTROL_PLANE_URL`: Django config endpoint URL (default: `http://django_dashboard:8000/api/waf/config/current`)
- `CONTROL_PLANE_TOKEN`: Bearer token for control plane authentication
- `CONTROL_PLANE_POLL_SECONDS`: Polling interval in seconds (default: 10)

**Django Dashboard:**
- `MONGODB_URI`: MongoDB Atlas connection string
- `MONGODB_NAME`: Database name (default: `waf_dashboard`)
- `DJANGO_SECRET_KEY`: Django secret key
- `DJANGO_ALLOWED_HOSTS`: Comma-separated list of allowed hosts
- `WAF_API_TOKEN`: Token for WAF to authenticate with Django config endpoint

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

**Initial Config:**
- Edit `configs/docker.yaml` to change initial rules, allowlist/blocklist and upstreams
- Default rules include PT001, SQLI001, XSS001, SSRF001, UA001

**Dynamic Config (Control Plane):**
- Use Django admin at `/dashboard/admin/` to manage:
  - WAF Rules (create/edit rules with `path_raw` target support)
  - Upstreams
  - Policy (thresholds, rate limits, WAF settings)
  - IP Allowlist/Blocklist
  - Trusted Proxies
- Click "Publish current config" action to deploy changes
- WAF automatically polls and reloads config (no restart needed)
- Config version is exposed as Prometheus metric `waf_config_version_info`

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
