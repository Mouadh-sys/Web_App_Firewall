# Mini WAF Reverse Proxy

This project implements a Web Application Firewall (WAF) reverse proxy using FastAPI. It is designed to inspect and filter incoming requests before forwarding them to upstream services.

## Features
- **Routing/Proxy Layer**: Forwards requests to upstream services with support for host/path-based routing.
- **Security Engine**: Detects malicious patterns and applies anomaly scoring.
- **Decision Layer**: Allows, blocks, or challenges requests based on security rules.
- **Observability**: Structured JSON logging and Prometheus metrics.
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

3. Run the application:
   ```bash
   uvicorn waf_proxy.main:app --reload
   ```

4. Run with Docker Compose:
   ```bash
   docker-compose up
   ```

### Configuration
- Modify `configs/example.yaml` to set up rules, upstreams, and thresholds.
- Use environment variables to override critical settings.

### Testing
Run unit and integration tests:
```bash
pytest
```

## Project Structure
```
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
