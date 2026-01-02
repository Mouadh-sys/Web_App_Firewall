from typing import List, Dict
from fastapi import Request

class Router:
    def __init__(self, upstreams: List[Dict]):
        self.upstreams = upstreams
        self.current_index = 0

    def get_upstream(self, request: Request) -> str:
        # Simple round-robin load balancing
        upstream = self.upstreams[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.upstreams)
        return upstream['url']
