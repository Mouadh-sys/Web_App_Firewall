from fastapi import Request
from starlette.responses import JSONResponse
from waf_proxy.waf.engine import SecurityEngine
from waf_proxy.proxy.proxy_client import ProxyClient
from waf_proxy.proxy.router import Router
from waf_proxy.waf.normalize import build_inspection_dict, get_client_ip

INTERNAL_PATHS = ('/metrics', '/readyz', '/healthz')

class WAFMiddleware:
    def __init__(self, app, config):
        self.app = app
        self.security_engine = SecurityEngine(config)
        self.router = Router(config['upstreams'])
        self.proxy_client = ProxyClient()

    async def __call__(self, scope, receive, send):
        request = Request(scope, receive)

        # Bypass internal endpoints so the application routes handle them
        if request.url.path in INTERNAL_PATHS:
            await self.app(scope, receive, send)
            return

        client_ip = get_client_ip(request)
        inspection = build_inspection_dict(request)

        result = self.security_engine.evaluate(inspection, client_ip)
        verdict = result.get('verdict')
        score = result.get('score', 0)
        findings = result.get('findings', [])
        rule_ids = [f.get('rule_id') for f in findings]

        # Always include headers with decision and score
        waf_headers = [
            (b'x-waf-decision', verdict.encode()),
            (b'x-waf-score', str(score).encode())
        ]

        if verdict == 'BLOCK':
            # Return 403 JSON with headers
            headers = {k.decode(): v.decode() for k, v in waf_headers}
            body = {
                'blocked': True,
                'reason': 'waf',
                'score': score,
                'rule_ids': rule_ids,
            }
            response = JSONResponse(content=body, status_code=403)
            # Attach headers
            response.headers.update(headers)
            await response(scope, receive, send)
            return
        else:
            # Forward request
            upstream_url = self.router.get_upstream(request)
            response = await self.proxy_client.forward_request(upstream_url, request)
            # Attach waf headers to forwarded response
            response.headers.update({k.decode(): v.decode() for k, v in waf_headers})
            await response(scope, receive, send)
