"""Hop-by-hop header handling for proxy forwarding."""

# Headers that should NOT be forwarded between hops
HOP_BY_HOP_HEADERS = {
    'connection',
    'keep-alive',
    'proxy-authenticate',
    'proxy-authorization',
    'te',
    'trailer',
    'transfer-encoding',
    'upgrade',
}

# Headers to remove in addition to hop-by-hop
HEADERS_TO_REMOVE = HOP_BY_HOP_HEADERS | {
    'content-length',  # Will be set by HTTP client
}

# X-Forwarding headers that indicate proxy hops
FORWARDING_HEADERS = {
    'x-forwarded-for',
    'x-forwarded-proto',
    'x-forwarded-host',
}


def should_forward_header(header_name: str) -> bool:
    """
    Check if a header should be forwarded to upstream.

    Args:
        header_name: Header name (case-insensitive)

    Returns:
        True if header should be forwarded, False otherwise
    """
    h = header_name.lower()
    return h not in HEADERS_TO_REMOVE


def filter_request_headers(headers: dict) -> dict:
    """
    Filter request headers for upstream forwarding.

    Removes hop-by-hop headers and keeps only safe headers to forward.
    Adds X-Forwarded-* headers.

    Args:
        headers: Raw request headers dictionary

    Returns:
        Filtered headers safe for upstream
    """
    # Parse Connection header to get additional headers to remove
    connection_tokens = set()
    connection_header = headers.get('connection', '')
    if connection_header:
        for token in connection_header.split(','):
            token = token.strip().lower()
            if token:
                connection_tokens.add(token)

    filtered = {}
    for key, value in headers.items():
        key_lower = key.lower()
        # Skip if it's a standard hop-by-hop header
        if not should_forward_header(key):
            continue
        # Skip if it's listed in Connection header
        if key_lower in connection_tokens:
            continue
        filtered[key] = value
    return filtered


def filter_response_headers(headers: dict) -> dict:
    """
    Filter response headers from upstream before sending to client.

    Removes hop-by-hop headers that should not cross proxy boundary.

    Args:
        headers: Raw response headers from upstream

    Returns:
        Filtered headers safe for client
    """
    # Parse Connection header to get additional headers to remove
    connection_tokens = set()
    connection_header = headers.get('connection', '')
    if connection_header:
        for token in connection_header.split(','):
            token = token.strip().lower()
            if token:
                connection_tokens.add(token)

    filtered = {}
    for key, value in headers.items():
        key_lower = key.lower()
        # Skip if it's a standard hop-by-hop header
        if not should_forward_header(key):
            continue
        # Skip if it's listed in Connection header
        if key_lower in connection_tokens:
            continue
        filtered[key] = value
    return filtered


def add_forwarding_headers(
    headers: dict,
    client_ip: str,
    original_scheme: str = 'http',
    original_host: str = 'localhost'
) -> dict:
    """
    Add or append X-Forwarded-* headers.

    Args:
        headers: Headers dictionary to modify
        client_ip: Client IP address
        original_scheme: Original request scheme (http/https)
        original_host: Original request Host header

    Returns:
        Headers with X-Forwarded-* added/appended
    """
    # X-Forwarded-For: append to existing or create
    xff = headers.get('x-forwarded-for', '')
    if xff:
        # Append to existing
        headers['x-forwarded-for'] = f"{xff}, {client_ip}"
    else:
        headers['x-forwarded-for'] = client_ip

    # X-Forwarded-Proto: set if not present
    if 'x-forwarded-proto' not in headers:
        headers['x-forwarded-proto'] = original_scheme

    # X-Forwarded-Host: set if not present
    if 'x-forwarded-host' not in headers:
        headers['x-forwarded-host'] = original_host

    return headers

