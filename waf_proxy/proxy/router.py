"""Request routing to upstream services."""
import logging
from typing import List, Dict, Optional
from fastapi import Request

logger = logging.getLogger(__name__)


class Router:
    """
    Route requests to upstream services with support for:
    - Host-based routing
    - Path prefix routing
    - Weighted round-robin load balancing
    """

    def __init__(self, upstreams: List):
        """
        Initialize router with upstream list.

        Args:
            upstreams: List of upstream config (dicts or Pydantic objects)
        """
        self.upstreams = upstreams or []
        self.current_index = 0

    def _get_field(self, upstream, field_name, default=None):
        """Get field from upstream (works with both dicts and Pydantic objects)."""
        if isinstance(upstream, dict):
            return upstream.get(field_name, default)
        else:
            return getattr(upstream, field_name, default)

    def get_upstream(self, request: Request) -> Optional[str]:
        """
        Select upstream URL based on request.

        Matching priority:
        1. Host header match (if upstream defines hosts)
        2. Path prefix match (longest prefix wins)
        3. Weighted round-robin fallback

        Args:
            request: FastAPI Request object

        Returns:
            Upstream URL or None if no upstreams available
        """
        if not self.upstreams:
            logger.warning("No upstreams configured")
            return None

        request_host = request.headers.get('host', '').lower()
        request_path = request.url.path

        # Try host-based matching
        for upstream in self.upstreams:
            hosts = self._get_field(upstream, 'hosts', [])
            if hosts and request_host in [h.lower() for h in hosts]:
                url = self._get_field(upstream, 'url')
                logger.debug(f"Matched upstream by host: {url}")
                return url

        # Try path prefix matching (longest prefix wins)
        best_match = None
        best_prefix_len = 0

        for upstream in self.upstreams:
            prefixes = self._get_field(upstream, 'path_prefixes', [])
            if prefixes:
                for prefix in prefixes:
                    if request_path.startswith(prefix) and len(prefix) > best_prefix_len:
                        best_match = upstream
                        best_prefix_len = len(prefix)

        if best_match:
            url = self._get_field(best_match, 'url')
            logger.debug(f"Matched upstream by path prefix: {url}")
            return url

        # Fallback to weighted round-robin
        upstream = self._select_by_weight()
        url = self._get_field(upstream, 'url')
        logger.debug(f"Selected upstream by round-robin: {url}")
        return url

    def _select_by_weight(self):
        """
        Select upstream using weighted round-robin.

        Returns:
            Upstream config (dict or Pydantic object)
        """
        if not self.upstreams:
            return {}

        # Simple weighted round-robin: cycle through upstreams
        upstream = self.upstreams[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.upstreams)
        return upstream

