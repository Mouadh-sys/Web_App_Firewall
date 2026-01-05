"""Configuration models using Pydantic."""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator
import ipaddress


class UpstreamConfig(BaseModel):
    """Configuration for an upstream service."""
    name: str
    url: str
    hosts: Optional[List[str]] = None
    path_prefixes: Optional[List[str]] = None
    weight: Optional[int] = 1
    healthcheck_path: Optional[str] = None

    @field_validator('weight')
    @classmethod
    def weight_positive(cls, v):
        if v is not None and v <= 0:
            raise ValueError('Weight must be positive')
        return v


class RuleConfig(BaseModel):
    """Configuration for a WAF rule."""
    id: str
    description: str
    target: str = Field(default='path', description='path, query, headers, or body')
    pattern: str
    score: int = 0
    enabled: bool = True


class RateLimitConfig(BaseModel):
    """Rate limit configuration."""
    requests_per_minute: int
    per_path: Optional[Dict[str, int]] = None  # path: requests_per_minute


class ThresholdsConfig(BaseModel):
    """WAF thresholds."""
    allow: int = 5
    challenge: int = 6
    block: int = 10


class ProxySettingsConfig(BaseModel):
    """Proxy client settings."""
    timeout_seconds: float = 30.0
    max_connections: int = 100
    max_keepalive_connections: int = 20
    keepalive_expiry: float = 5.0
    retries: int = 0


class WAFSettingsConfig(BaseModel):
    """WAF behavior settings."""
    mode: str = Field(default='block', description='monitor or block')
    max_inspect_bytes: int = 10000
    max_body_bytes: int = 1000000
    inspect_body: bool = False

    @field_validator('mode')
    @classmethod
    def mode_valid(cls, v):
        if v not in ('monitor', 'block'):
            raise ValueError('Mode must be monitor or block')
        return v


class Config(BaseModel):
    """Main WAF Proxy configuration."""
    upstreams: List[UpstreamConfig]
    ip_allowlist: Optional[List[str]] = None
    ip_blocklist: Optional[List[str]] = None
    trusted_proxies: Optional[List[str]] = None  # CIDR ranges
    rules: Optional[List[RuleConfig]] = None
    thresholds: Optional[ThresholdsConfig] = None
    rate_limits: Optional[RateLimitConfig] = None
    proxy_settings: Optional[ProxySettingsConfig] = None
    waf_settings: Optional[WAFSettingsConfig] = None

    def __init__(self, **data):
        super().__init__(**data)
        # Validate CIDR ranges
        if self.trusted_proxies:
            for cidr in self.trusted_proxies:
                try:
                    ipaddress.ip_network(cidr, strict=False)
                except ValueError as e:
                    raise ValueError(f'Invalid CIDR range "{cidr}": {e}')
        if self.ip_allowlist:
            for entry in self.ip_allowlist:
                try:
                    # Try as IP address first
                    ipaddress.ip_address(entry)
                except ValueError:
                    try:
                        # If not an IP, try as CIDR network
                        ipaddress.ip_network(entry, strict=False)
                    except ValueError as e:
                        raise ValueError(f'Invalid IP or CIDR in allowlist "{entry}": {e}')
        if self.ip_blocklist:
            for entry in self.ip_blocklist:
                try:
                    # Try as IP address first
                    ipaddress.ip_address(entry)
                except ValueError:
                    try:
                        # If not an IP, try as CIDR network
                        ipaddress.ip_network(entry, strict=False)
                    except ValueError as e:
                        raise ValueError(f'Invalid IP or CIDR in blocklist "{entry}": {e}')

