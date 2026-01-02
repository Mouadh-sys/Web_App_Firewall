from prometheus_client import Counter, Histogram

# Define Prometheus metrics
request_counter = Counter(
    'requests_total',
    'Total number of requests',
    ['verdict', 'status']
)

rule_hits_counter = Counter(
    'waf_rule_hits_total',
    'Total number of WAF rule hits',
    ['rule_id']
)

upstream_latency = Histogram(
    'upstream_latency_seconds',
    'Latency of upstream requests in seconds'
)

def record_request(verdict, status):
    request_counter.labels(verdict=verdict, status=status).inc()

def record_rule_hit(rule_id):
    rule_hits_counter.labels(rule_id=rule_id).inc()

def record_upstream_latency(latency):
    upstream_latency.observe(latency)
