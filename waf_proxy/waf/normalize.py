from urllib.parse import unquote

def _multi_urldecode(s: str, times: int = 2) -> str:
    if not s:
        return ''
    result = s
    for _ in range(times):
        try:
            result = unquote(result)
        except Exception:
            break
    return result


def get_client_ip(request) -> str:
    # Prefer X-Forwarded-For if present
    xff = request.headers.get('x-forwarded-for')
    if xff:
        # take first IP
        first = xff.split(',')[0].strip()
        return first
    # Fallback to request.client.host
    return request.client.host


def normalize_path(path: str) -> str:
    if path is None:
        return ''
    p = path
    # decode up to 2 times
    p = _multi_urldecode(p, times=2)
    # replace backslashes
    p = p.replace('\\', '/')
    # remove null bytes
    p = p.replace('\x00', '')
    # collapse multiple slashes
    while '//' in p:
        p = p.replace('//', '/')
    return p


def normalize_query(query_string: str) -> str:
    if query_string is None:
        return ''
    q = query_string
    q = _multi_urldecode(q, times=2)
    q = q.replace('\x00', '')
    return q


def extract_headers_subset(request) -> str:
    parts = []
    for h in ('user-agent', 'referer', 'content-type'):
        v = request.headers.get(h)
        if v:
            parts.append(f"{h}:{v}")
    return ' '.join(parts)


def build_inspection_dict(request) -> dict:
    path = normalize_path(request.url.path)
    # Build query string from request.url.query if present
    raw_query = request.url.query
    query = normalize_query(raw_query)
    headers = extract_headers_subset(request)
    return {
        'path': path,
        'query': query,
        'headers': headers,
    }
