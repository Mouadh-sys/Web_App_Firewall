from fastapi import Request
from waf_proxy.waf.engine import SecurityEngine
from waf_proxy.proxy.proxy_client import ProxyClient
from waf_proxy.proxy.router import Router

class WAFMiddleware:
    def __init__(self, app, config):
        self.app = app
        self.security_engine = SecurityEngine(config)
        self.router = Router(config['upstreams'])
        self.proxy_client = ProxyClient()

    async def __call__(self, scope, receive, send):
        request = Request(scope, receive)
        findings = self.security_engine.evaluate(request)
        decision = self.security_engine.decide(findings)

        if decision['verdict'] == 'BLOCK':
            await send({
                'type': 'http.response.start',
                'status': 403,
                'headers': [(b'content-type', b'application/json')]
            })
            await send({
                'type': 'http.response.body',
                'body': b'{"error": "Request blocked by WAF"}'
            })
        else:
            upstream_url = self.router.get_upstream(request)
            response = await self.proxy_client.forward_request(upstream_url, request)
            await response(scope, receive, send)
