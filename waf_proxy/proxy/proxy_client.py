import httpx
from fastapi import Request, Response

class ProxyClient:
    def __init__(self):
        self.client = httpx.AsyncClient()

    async def forward_request(self, upstream_url: str, request: Request) -> Response:
        # Forward the request to the upstream service
        headers = {key: value for key, value in request.headers.items() if key.lower() != 'host'}
        response = await self.client.request(
            method=request.method,
            url=f"{upstream_url}{request.url.path}?{request.url.query}",
            headers=headers,
            content=await request.body()
        )
        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=dict(response.headers)
        )
