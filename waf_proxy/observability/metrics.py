"""Prometheus metrics for WAF observability."""
from prometheus_client import Counter, Histogram, generate_latest, REGISTRY

# Request metrics
requests_total = Counter(
    'requests_total',
    'Total number of requests',
    ['verdict', 'status']
)

# WAF rule hits
rule_hits_counter = Counter(
    'waf_rule_hits_total',
    'Total number of WAF rule hits',
    ['rule_id']
)

# Rate limiting
rate_limited_total = Counter(
    'rate_limited_requests_total',
    'Total number of rate-limited requests',
    ['client_ip']
)

# Upstream latency
upstream_latency = Histogram(
    'upstream_latency_seconds',
    'Latency of upstream requests in seconds',
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
)

# Upstream errors
upstream_errors_total = Counter(
    'upstream_errors_total',
    'Total number of upstream errors',
    ['error_type']
)


def record_request(verdict: str, status: int) -> None:
    """Record request metrics."""
    requests_total.labels(verdict=verdict, status=status).inc()


def record_rule_hit(rule_id: str) -> None:
    """Record rule hit metric."""
    rule_hits_counter.labels(rule_id=rule_id).inc()


def record_rate_limit(client_ip: str) -> None:
    """Record rate limit block."""
    rate_limited_total.labels(client_ip=client_ip).inc()


def record_upstream_latency(latency: float) -> None:
    """Record upstream response latency."""
    upstream_latency.observe(latency)


def record_upstream_error(error_type: str) -> None:
    """Record upstream error."""
    upstream_errors_total.labels(error_type=error_type).inc()


def get_metrics_text() -> str:
    """
    Get Prometheus metrics in text format.

    Returns:
        Prometheus plaintext format string
    """
    return generate_latest(REGISTRY).decode('utf-8')


