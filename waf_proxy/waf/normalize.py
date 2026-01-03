"""Request normalization and inspection utilities."""
from urllib.parse import unquote
import ipaddress
import posixpath
from typing import List, Optional


def _multi_urldecode(s: str, times: int = 2) -> str:
    """Safely decode percent-encoded strings up to N times."""
    if not s:
        return ''
    result = s
    for _ in range(times):
        try:
            result = unquote(result)
        except Exception:
            break
    return result


def get_client_ip(request, trusted_proxies: Optional[List[str]] = None) -> str:
    """
    Extract client IP from request, respecting trusted proxy list.

    Args:
        request: FastAPI Request object
        trusted_proxies: List of CIDR ranges for trusted proxies

    Returns:
        Client IP address (string)
    """
    # Get peer IP (immediate connection source)
    peer_ip = request.client.host if request.client else '0.0.0.0'

    # If no trusted proxies, always use peer IP
    if not trusted_proxies:
        return peer_ip

    # Check if peer IP is in trusted proxy list
    peer_trusted = False
    try:
        peer_addr = ipaddress.ip_address(peer_ip)
        for cidr_str in trusted_proxies:
            cidr = ipaddress.ip_network(cidr_str, strict=False)
            if peer_addr in cidr:
                peer_trusted = True
                break
    except ValueError:
        # Invalid peer IP, fallback to peer IP
        return peer_ip

    # If peer is trusted, use X-Forwarded-For (left-most = original client)
    if peer_trusted:
        xff = request.headers.get('x-forwarded-for')
        if xff:
            try:
                # Take the left-most (first) IP
                first_ip = xff.split(',')[0].strip()
                ipaddress.ip_address(first_ip)  # Validate
                return first_ip
            except (ValueError, IndexError):
                pass

    # Fallback to peer IP
    return peer_ip


def normalize_path(path: str) -> str:
    """
    Normalize path: decode, remove nulls, collapse slashes, normalize.

    Args:
        path: Raw URL path

    Returns:
        Normalized path with leading slash preserved
    """
    if path is None:
        return '/'

    p = path
    # Decode up to 2 times
    p = _multi_urldecode(p, times=2)
    # Replace backslashes with forward slashes
    p = p.replace('\\', '/')
    # Remove null bytes
    p = p.replace('\x00', '')
    # Use posixpath.normpath for canonical normalization
    p = posixpath.normpath(p)
    # Ensure leading slash
    if not p.startswith('/'):
        p = '/' + p

    return p


def normalize_query(query_string: str) -> str:
    """
    Normalize query string: decode, remove nulls.

    Args:
        query_string: Raw query string

    Returns:
        Normalized query string
    """
    if query_string is None:
        return ''
    q = query_string
    q = _multi_urldecode(q, times=2)
    q = q.replace('\x00', '')
    return q


def extract_headers_subset(request) -> str:
    """
    Extract inspection-relevant headers.

    Args:
        request: FastAPI Request object

    Returns:
        Space-separated header values (lowercased)
    """
    parts = []
    for h in ('user-agent', 'referer', 'content-type', 'accept', 'host'):
        v = request.headers.get(h)
        if v:
            parts.append(f"{h}:{v}".lower())
    return ' '.join(parts)


def build_inspection_dict(request, max_inspect_bytes: int = 10000) -> dict:
    """
    Build inspection context from request.

    Args:
        request: FastAPI Request object
        max_inspect_bytes: Maximum bytes to inspect (truncation limit)

    Returns:
        Dictionary with normalized path, query, headers for rule matching
    """
    path = normalize_path(request.url.path)
    raw_query = request.url.query
    query = normalize_query(raw_query)
    headers = extract_headers_subset(request)

    # Truncate to avoid regex DoS
    path = path[:max_inspect_bytes]
    query = query[:max_inspect_bytes]
    headers = headers[:max_inspect_bytes]

    return {
        'path': path,
        'query': query,
        'headers': headers,
    }
