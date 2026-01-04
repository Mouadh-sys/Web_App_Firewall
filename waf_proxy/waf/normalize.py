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
    Implements safe "walk from the right" logic to remove trusted proxies.

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

    # If peer is NOT trusted, ignore XFF and return peer IP
    if not peer_trusted:
        return peer_ip

    # Peer is trusted: parse XFF and walk from the right
    xff = request.headers.get('x-forwarded-for')
    if not xff:
        return peer_ip

    # Parse XFF into list of IPs
    xff_list = []
    for entry in xff.split(','):
        entry = entry.strip()
        if entry:
            try:
                ipaddress.ip_address(entry)  # Validate
                xff_list.append(entry)
            except ValueError:
                # Skip invalid entries
                continue

    # Build chain: xff_list + [peer_ip]
    chain = xff_list + [peer_ip]

    # Build set of trusted IP networks for quick lookup
    trusted_networks = []
    for cidr_str in trusted_proxies:
        try:
            trusted_networks.append(ipaddress.ip_network(cidr_str, strict=False))
        except ValueError:
            continue

    # Remove trusted proxies from the RIGHT side
    while chain:
        last_ip = chain[-1]
        try:
            last_addr = ipaddress.ip_address(last_ip)
            # Check if last IP is in any trusted network
            is_trusted = False
            for trusted_net in trusted_networks:
                if last_addr in trusted_net:
                    is_trusted = True
                    break
            if is_trusted:
                chain.pop()
            else:
                # Found untrusted IP, this is the client
                break
        except ValueError:
            # Invalid IP, remove it
            chain.pop()

    # Return the last remaining element if any; otherwise fallback to peer_ip
    if chain:
        return chain[-1]
    return peer_ip


def decode_path(path: str) -> str:
    """
    Decode path: percent-decode, remove null bytes, replace backslashes.
    DOES NOT canonicalize (no normpath) to preserve traversal markers for WAF inspection.

    Args:
        path: Raw URL path

    Returns:
        Decoded path (NOT canonicalized)
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
    # Ensure leading slash
    if not p.startswith('/'):
        p = '/' + p

    return p


def canonicalize_path(decoded_path: str) -> str:
    """
    Canonicalize a decoded path using normpath.

    Args:
        decoded_path: Already decoded path (from decode_path)

    Returns:
        Canonicalized path with leading slash preserved
    """
    if decoded_path is None:
        return '/'

    p = decoded_path
    # Use posixpath.normpath for canonical normalization
    p = posixpath.normpath(p)
    # Ensure leading slash
    if not p.startswith('/'):
        p = '/' + p

    return p


def normalize_path(path: str) -> str:
    """
    Normalize path: decode and canonicalize.
    DEPRECATED: Use decode_path() and canonicalize_path() separately for WAF inspection.

    Args:
        path: Raw URL path

    Returns:
        Normalized path with leading slash preserved
    """
    decoded = decode_path(path)
    return canonicalize_path(decoded)


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


def build_inspection_dict(request, max_inspect_bytes: int = 10000, body_bytes: Optional[bytes] = None) -> dict:
    """
    Build inspection context from request.

    Args:
        request: FastAPI Request object
        max_inspect_bytes: Maximum bytes to inspect (truncation limit)
        body_bytes: Optional request body bytes (if inspect_body is enabled)

    Returns:
        Dictionary with path_raw (decoded, not canonicalized), path (canonicalized),
        query, headers, and optionally body for rule matching
    """
    # Decode path without canonicalization (preserves traversal markers)
    path_raw = decode_path(request.url.path)
    # Also provide canonicalized path for backward compatibility
    path = canonicalize_path(path_raw)
    
    raw_query = request.url.query
    query = normalize_query(raw_query)
    headers = extract_headers_subset(request)

    # Truncate to avoid regex DoS
    path_raw = path_raw[:max_inspect_bytes]
    path = path[:max_inspect_bytes]
    query = query[:max_inspect_bytes]
    headers = headers[:max_inspect_bytes]

    result = {
        'path_raw': path_raw,  # Decoded, NOT canonicalized (for traversal detection)
        'path': path,  # Canonicalized (for backward compatibility)
        'query': query,
        'headers': headers,
    }

    # Include body if provided and within limit
    if body_bytes is not None:
        body_str = body_bytes[:max_inspect_bytes].decode('utf-8', errors='replace')
        result['body'] = body_str

    return result
