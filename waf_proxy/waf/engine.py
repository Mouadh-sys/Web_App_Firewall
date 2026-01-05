"""Security engine for request inspection and scoring."""
import re
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


def _to_dict(obj):
    """Convert Pydantic model to dict if needed."""
    if hasattr(obj, 'model_dump'):
        return obj.model_dump()
    elif hasattr(obj, 'dict'):
        return obj.dict()
    return obj


class SecurityEngine:
    """
    WAF security engine that:
    - Evaluates requests against configured rules
    - Scores violations
    - Makes verdict decisions (ALLOW / SUSPICIOUS / BLOCK)
    - Respects monitor vs. block mode
    """

    def __init__(self, config):
        """
        Initialize security engine from config.

        Args:
            config: Pydantic Config object or dict with rules, thresholds, ip_allowlist, ip_blocklist
        """
        # Convert Pydantic model to dict if needed
        config = _to_dict(config)

        self.config = config or {}

        # IP lists - support both IP addresses and CIDR ranges
        self.ip_allowlist = self._parse_ip_list(self.config.get('ip_allowlist') or [])
        self.ip_blocklist = self._parse_ip_list(self.config.get('ip_blocklist') or [])

        # Thresholds
        thresholds_cfg = self.config.get('thresholds') or {}
        thresholds_cfg = _to_dict(thresholds_cfg)

        self.allow_threshold = thresholds_cfg.get('allow', 5)
        self.challenge_threshold = thresholds_cfg.get('challenge', 6)
        self.block_threshold = thresholds_cfg.get('block', 10)

        # WAF mode
        waf_cfg = self.config.get('waf_settings') or {}
        waf_cfg = _to_dict(waf_cfg)

        self.mode = waf_cfg.get('mode', 'block')  # 'block' or 'monitor'
        self.max_inspect_bytes = waf_cfg.get('max_inspect_bytes', 10000)

        # Compile rules
        self.rules = []
        raw_rules = self.config.get('rules') or []

        for r in raw_rules:
            # Support both dict and Pydantic objects
            r = _to_dict(r)

            enabled = r.get('enabled', True)
            pattern_text = r.get('pattern', '')

            try:
                compiled = re.compile(pattern_text)
            except re.error as e:
                logger.warning(f"Skipping rule {r.get('id')} due to invalid regex: {e}")
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

        logger.info(f"Security engine initialized with {len(self.rules)} rules (mode: {self.mode})")

    def _parse_ip_list(self, entries: List[str]) -> List:
        """
        Parse IP allowlist/blocklist entries into a list of IP addresses and networks.
        
        Args:
            entries: List of IP addresses or CIDR ranges (strings)
            
        Returns:
            List of ipaddress.IPv4Address, ipaddress.IPv6Address, or ipaddress.IPNetwork objects
        """
        import ipaddress
        result = []
        for entry in entries:
            try:
                # Try as IP address first
                result.append(ipaddress.ip_address(entry))
            except ValueError:
                try:
                    # If not an IP, try as CIDR network
                    result.append(ipaddress.ip_network(entry, strict=False))
                except ValueError:
                    logger.warning(f"Invalid IP or CIDR in list: {entry}, skipping")
        return result

    def _ip_in_list(self, client_ip: str, ip_list: List) -> bool:
        """
        Check if client IP is in the given list (supports both IP addresses and CIDR ranges).
        
        Args:
            client_ip: Client IP address (string)
            ip_list: List of ipaddress objects (IPAddress or IPNetwork)
            
        Returns:
            True if client IP matches any entry in the list
        """
        import ipaddress
        try:
            client_addr = ipaddress.ip_address(client_ip)
            for entry in ip_list:
                if isinstance(entry, ipaddress.IPAddress):
                    if client_addr == entry:
                        return True
                elif isinstance(entry, ipaddress.IPNetwork):
                    if client_addr in entry:
                        return True
        except ValueError:
            # Invalid client IP, can't match
            pass
        return False

    def evaluate(self, inspection: Dict, client_ip: str) -> Dict:
        """
        Evaluate request and return verdict.

        Args:
            inspection: Dict with keys 'path', 'query', 'headers' (normalized strings)
            client_ip: Client IP address

        Returns:
            Dict with:
                - verdict: 'ALLOW' | 'SUSPICIOUS' | 'BLOCK'
                - score: integer total score
                - findings: list of matched rules
                - rule_ids: list of matched rule IDs
        """
        findings = []

        # Fast-path: IP allowlist (always allow)
        if self._ip_in_list(client_ip, self.ip_allowlist):
            findings.append({
                'rule_id': 'allowlist',
                'description': 'IP in allowlist',
                'target': 'ip',
                'score': 0,
            })
            return {
                'verdict': 'ALLOW',
                'score': 0,
                'findings': findings,
                'rule_ids': ['allowlist'],
            }

        # Fast-path: IP blocklist (always block, but mode may soften)
        if self._ip_in_list(client_ip, self.ip_blocklist):
            findings.append({
                'rule_id': 'blocklist',
                'description': 'IP in blocklist',
                'target': 'ip',
                'score': 100,  # High score to force block even with low threshold
            })
            total_score = 100
            verdict = self._decide_verdict(total_score)
            return {
                'verdict': verdict,
                'score': total_score,
                'findings': findings,
                'rule_ids': ['blocklist'],
            }

        # Evaluate rules
        for rule in self.rules:
            if not rule.get('enabled', True):
                continue

            target_field = rule.get('target', 'path')
            text = inspection.get(target_field, '') or ''

            # Truncate to avoid regex DoS
            text = text[:self.max_inspect_bytes]

            try:
                if rule['pattern'].search(text):
                    findings.append({
                        'rule_id': rule.get('id'),
                        'description': rule.get('description'),
                        'target': target_field,
                        'score': rule.get('score', 0),
                    })

                    # Record metric
                    from waf_proxy.observability.metrics import record_rule_hit
                    record_rule_hit(rule.get('id'))

            except re.error as e:
                logger.warning(f"Error applying rule {rule.get('id')}: {e}")
            except Exception as e:
                logger.warning(f"Unexpected error in rule {rule.get('id')}: {e}")

        total_score = sum(f.get('score', 0) for f in findings)
        verdict = self._decide_verdict(total_score)
        rule_ids = [f.get('rule_id') for f in findings if f.get('rule_id')]

        return {
            'verdict': verdict,
            'score': total_score,
            'findings': findings,
            'rule_ids': rule_ids,
        }

    def _decide_verdict(self, score: int) -> str:
        """
        Decide verdict based on score and thresholds.

        Logic:
        - ALLOW if score <= allow_threshold
        - SUSPICIOUS if allow_threshold < score < block_threshold
        - BLOCK if score >= block_threshold

        In monitor mode: never return BLOCK, only ALLOW/SUSPICIOUS.
        In block mode: return ALLOW/SUSPICIOUS/BLOCK based on thresholds.

        Args:
            score: Total security score

        Returns:
            Verdict string: ALLOW | SUSPICIOUS | BLOCK
        """
        if score >= self.block_threshold:
            verdict = 'BLOCK'
        elif score > self.allow_threshold:
            # allow_threshold < score < block_threshold
            verdict = 'SUSPICIOUS'
        else:
            # score <= allow_threshold
            verdict = 'ALLOW'

        # In monitor mode, never block
        if self.mode == 'monitor' and verdict == 'BLOCK':
            verdict = 'SUSPICIOUS'

        return verdict

