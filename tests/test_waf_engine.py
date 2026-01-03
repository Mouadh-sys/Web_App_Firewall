from waf_proxy.waf.engine import SecurityEngine

class DummyRequest:
    def __init__(self, path='/', query='', headers=None, client_host='1.2.3.4'):
        self.url = type('u', (), {'path': path, 'query': query})
        self.headers = headers or {}
        self.client = type('c', (), {'host': client_host})


def test_allowlist_short_circuits():
    config = {'ip_allowlist': ['1.1.1.1'], 'rules': []}
    engine = SecurityEngine(config)
    req = DummyRequest(client_host='1.1.1.1')
    res = engine.evaluate({'path': '/', 'query': '', 'headers': ''}, '1.1.1.1')
    assert res['verdict'] == 'ALLOW'
    assert res['score'] == 0


def test_blocklist_blocks():
    config = {'ip_blocklist': ['2.2.2.2'], 'rules': []}
    engine = SecurityEngine(config)
    res = engine.evaluate({'path': '/', 'query': '', 'headers': ''}, '2.2.2.2')
    assert res['verdict'] == 'BLOCK'
    assert res['score'] >= 10


def test_path_traversal_rule_matches():
    config = {
        'rules': [
            {'id': 'PT001', 'description': 'pt', 'target': 'path', 'pattern': r"(\.\./|%2e%2e%2f|%2e%2e\\)", 'score': 10}
        ]
    }
    engine = SecurityEngine(config)
    inspection = {'path': '/../etc/passwd', 'query': '', 'headers': ''}
    res = engine.evaluate(inspection, '3.3.3.3')
    assert res['verdict'] == 'BLOCK'


def test_suspicious_aggregation():
    config = {
        'rules': [
            {'id': 'UA001', 'description': 'ua', 'target': 'headers', 'pattern': r"(?i)(sqlmap)", 'score': 6},
        ]
    }
    engine = SecurityEngine(config)
    inspection = {'path': '/', 'query': '', 'headers': 'user-agent:sqlmap'}
    res = engine.evaluate(inspection, '4.4.4.4')
    assert res['verdict'] == 'SUSPICIOUS'
    assert res['score'] == 6

