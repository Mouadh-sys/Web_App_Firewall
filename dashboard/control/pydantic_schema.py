"""Pydantic schema matching WAF config structure for validation."""
from typing import List, Optional, Dict
from pydantic import BaseModel, Field


class UpstreamConfig(BaseModel):
    name: str
    url: str
    hosts: Optional[List[str]] = None
    path_prefixes: Optional[List[str]] = None
    weight: Optional[int] = 1
    healthcheck_path: Optional[str] = None


class RuleConfig(BaseModel):
    id: str
    description: str
    target: str = Field(default='path', description='path, path_raw, query, headers, or body')
    pattern: str
    score: int = 0
    enabled: bool = True


class RateLimitConfig(BaseModel):
    requests_per_minute: int
    per_path: Optional[Dict[str, int]] = None


class ThresholdsConfig(BaseModel):
    allow: int = 5
    challenge: int = 6
    block: int = 10


class ProxySettingsConfig(BaseModel):
    timeout_seconds: float = 30.0
    max_connections: int = 100
    max_keepalive_connections: int = 20
    keepalive_expiry: float = 5.0
    retries: int = 0


class WAFSettingsConfig(BaseModel):
    mode: str = Field(default='block', description='monitor or block')
    max_inspect_bytes: int = 10000
    max_body_bytes: int = 1000000
    inspect_body: bool = False


class Config(BaseModel):
    """Main WAF Proxy configuration schema."""
    upstreams: List[UpstreamConfig]
    ip_allowlist: Optional[List[str]] = None
    ip_blocklist: Optional[List[str]] = None
    trusted_proxies: Optional[List[str]] = None
    rules: Optional[List[RuleConfig]] = None
    thresholds: Optional[ThresholdsConfig] = None
    rate_limits: Optional[RateLimitConfig] = None
    proxy_settings: Optional[ProxySettingsConfig] = None
    waf_settings: Optional[WAFSettingsConfig] = None

