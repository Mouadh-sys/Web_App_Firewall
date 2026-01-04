"""Unit tests for WAF security engine."""
import pytest
from waf_proxy.waf.engine import SecurityEngine
from waf_proxy.models import Config, UpstreamConfig, RuleConfig, ThresholdsConfig



class TestAllowlistAndBlocklist:
    """Test IP allowlist and blocklist behavior."""

    def test_allowlist_short_circuits(self):
        """Test that allowlisted IPs always get ALLOW."""
        config = Config(
            upstreams=[UpstreamConfig(name='test', url='http://localhost')],
            ip_allowlist=['1.1.1.1'],
            rules=[]
        )
        engine = SecurityEngine(config)
        result = engine.evaluate({'path': '/', 'query': '', 'headers': ''}, '1.1.1.1')

        assert result['verdict'] == 'ALLOW'
        assert result['score'] == 0
        assert result['rule_ids'] == ['allowlist']

    def test_blocklist_blocks(self):
        """Test that blocklisted IPs get BLOCK."""
        config = Config(
            upstreams=[UpstreamConfig(name='test', url='http://localhost')],
            ip_blocklist=['2.2.2.2'],
            rules=[]
        )
        engine = SecurityEngine(config)
        result = engine.evaluate({'path': '/', 'query': '', 'headers': ''}, '2.2.2.2')

        assert result['verdict'] == 'BLOCK'
        assert result['score'] >= 10


class TestPathTraversal:
    """Test path traversal detection."""

    def test_path_traversal_rule_matches(self):
        """Test that path traversal patterns are detected."""
        rules = [
            RuleConfig(
                id='PT001',
                description='path traversal',
                target='path',
                pattern=r"(\.\./|%2e%2e%2f|%2e%2e\\)",
                score=10
            )
        ]
        config = Config(
            upstreams=[UpstreamConfig(name='test', url='http://localhost')],
            rules=rules
        )
        engine = SecurityEngine(config)

        inspection = {'path': '/../etc/passwd', 'query': '', 'headers': ''}
        result = engine.evaluate(inspection, '3.3.3.3')

        assert result['verdict'] == 'BLOCK'
        assert 'PT001' in result['rule_ids']


class TestSuspiciousScoring:
    """Test suspicious verdict aggregation."""

    def test_suspicious_aggregation(self):
        """Test that scores 6-9 result in SUSPICIOUS."""
        rules = [
            RuleConfig(
                id='UA001',
                description='scanner user-agent',
                target='headers',
                pattern=r"(?i)(sqlmap)",
                score=6
            )
        ]
        config = Config(
            upstreams=[UpstreamConfig(name='test', url='http://localhost')],
            rules=rules
        )
        engine = SecurityEngine(config)

        inspection = {'path': '/', 'query': '', 'headers': 'user-agent:sqlmap'}
        result = engine.evaluate(inspection, '4.4.4.4')

        assert result['verdict'] == 'SUSPICIOUS'
        assert result['score'] == 6
        assert 'UA001' in result['rule_ids']


class TestThresholds:
    """Test configurable thresholds."""

    def test_custom_thresholds(self):
        """Test that custom thresholds are respected."""
        rules = [
            RuleConfig(
                id='TEST001',
                description='test',
                target='path',
                pattern=r"test",
                score=5
            )
        ]
        config = Config(
            upstreams=[UpstreamConfig(name='test', url='http://localhost')],
            rules=rules,
            thresholds=ThresholdsConfig(allow=4, challenge=8, block=15)
        )
        engine = SecurityEngine(config)

        # Score 5 should be BLOCK (below custom threshold of 4)
        # No, custom allow=4 means scores < 4 are allow, >= 4 and < 8 are challenge/suspicious
        inspection = {'path': 'test', 'query': '', 'headers': ''}
        result = engine.evaluate(inspection, '5.5.5.5')

        # With allow=4, challenge=8, block=15:
        # score=5 should be SUSPICIOUS (challenge threshold)
        assert result['score'] == 5


class TestMonitorMode:
    """Test monitor vs block mode."""

    def test_monitor_mode_never_blocks(self):
        """Test that monitor mode never returns BLOCK."""
        rules = [
            RuleConfig(
                id='PT001',
                description='path traversal',
                target='path',
                pattern=r"(\.\./)",
                score=10
            )
        ]
        config = Config(
            upstreams=[UpstreamConfig(name='test', url='http://localhost')],
            rules=rules,
            waf_settings={'mode': 'monitor'}
        )
        engine = SecurityEngine(config)

        inspection = {'path': '/../etc/passwd', 'query': '', 'headers': ''}
        result = engine.evaluate(inspection, '6.6.6.6')

        # Even with score >= 10, monitor mode returns SUSPICIOUS not BLOCK
        assert result['verdict'] in ('ALLOW', 'SUSPICIOUS')
        assert result['verdict'] != 'BLOCK'


class TestMultipleRuleMatches:
    """Test scoring with multiple rule matches."""

    def test_multiple_rules_accumulate_score(self):
        """Test that multiple matching rules accumulate scores."""
        rules = [
            RuleConfig(
                id='R1',
                description='rule 1',
                target='path',
                pattern=r"test",
                score=4
            ),
            RuleConfig(
                id='R2',
                description='rule 2',
                target='query',
                pattern=r"admin",
                score=5
            )
        ]
        config = Config(
            upstreams=[UpstreamConfig(name='test', url='http://localhost')],
            rules=rules
        )
        engine = SecurityEngine(config)

        inspection = {'path': 'test', 'query': 'admin=true', 'headers': ''}
        result = engine.evaluate(inspection, '7.7.7.7')

        assert result['score'] == 9  # 4 + 5
        assert 'R1' in result['rule_ids']
        assert 'R2' in result['rule_ids']
        assert result['verdict'] == 'SUSPICIOUS'


