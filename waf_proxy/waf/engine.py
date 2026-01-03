import re
import logging
from typing import Dict

class SecurityEngine:
    def __init__(self, config: Dict):
        self.config = config or {}
        self.ip_allowlist = set(self.config.get('ip_allowlist', []))
        self.ip_blocklist = set(self.config.get('ip_blocklist', []))
        self.rules = []
        raw_rules = self.config.get('rules', []) or []
        for r in raw_rules:
            enabled = r.get('enabled', True)
            pattern_text = r.get('pattern', '')
            try:
                compiled = re.compile(pattern_text)
            except re.error as e:
                logging.warning(f"Skipping rule %s due to invalid regex: %s", r.get('id'), e)
                continue
            rule = {
                'id': r.get('id'),
                'description': r.get('description'),
                'target': r.get('target', 'path'),
                'pattern': compiled,
                'pattern_text': pattern_text,
                'score': int(r.get('score', 0)),
                'enabled': enabled,
            }
            self.rules.append(rule)

    def evaluate(self, inspection: Dict, client_ip: str) -> Dict:
        """
        inspection: dict with keys 'path','query','headers' (strings)
        client_ip: string

        Returns a dict: {verdict, score, findings}
        """
        findings = []

        # Allowlist/Blocklist fast-path
        if client_ip in self.ip_allowlist:
            findings.append({
                'rule_id': 'allowlist',
                'description': 'IP in allowlist',
                'target': 'ip',
                'pattern': client_ip,
                'score': 0,
            })
            return {'verdict': 'ALLOW', 'score': 0, 'findings': findings}

        if client_ip in self.ip_blocklist:
            findings.append({
                'rule_id': 'blocklist',
                'description': 'IP in blocklist',
                'target': 'ip',
                'pattern': client_ip,
                'score': 10,
            })
            return {'verdict': 'BLOCK', 'score': 10, 'findings': findings}

        # Evaluate rules
        for rule in self.rules:
            if not rule.get('enabled', True):
                continue
            target_field = rule.get('target', 'path')
            text = inspection.get(target_field, '') or ''
            # If headers target, we expect a string concatenation already
            try:
                if rule['pattern'].search(text):
                    findings.append({
                        'rule_id': rule.get('id'),
                        'description': rule.get('description'),
                        'target': target_field,
                        'pattern': rule.get('pattern_text'),
                        'score': rule.get('score', 0),
                    })
            except re.error as e:
                logging.warning("Error applying rule %s: %s", rule.get('id'), e)
                continue

        total_score = sum(f.get('score', 0) for f in findings)
        if total_score >= 10:
            verdict = 'BLOCK'
        elif 6 <= total_score <= 9:
            verdict = 'SUSPICIOUS'
        else:
            verdict = 'ALLOW'

        return {'verdict': verdict, 'score': total_score, 'findings': findings}

    def decide(self, findings):
        # Backwards-compatible wrapper (existing code used decide(findings))
        score = sum(f['score'] for f in findings)
        if score >= 10:
            return {'verdict': 'BLOCK'}
        return {'verdict': 'ALLOW'}
