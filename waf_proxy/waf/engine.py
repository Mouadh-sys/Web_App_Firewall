import re
from fastapi import Request

class SecurityEngine:
    def __init__(self, config):
        self.rules = config['rules']

    def evaluate(self, request: Request):
        findings = []
        for rule in self.rules:
            target = request.url.path if rule['target'] == 'path' else ''
            if re.search(rule['pattern'], target):
                findings.append(rule)
        return findings

    def decide(self, findings):
        score = sum(rule['score'] for rule in findings)
        if score >= 10:
            return {'verdict': 'BLOCK'}
        return {'verdict': 'ALLOW'}
