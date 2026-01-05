import hashlib, json
from django.db import transaction
from .models import Upstream, WAFRule, Policy, IpListEntry, TrustedProxy, ConfigVersion
from .pydantic_schema import Config as PydanticConfig  # you create this below

def build_config_dict() -> dict:
    policy = Policy.objects.first()
    if not policy:
        policy = Policy.objects.create()

    upstreams = list(Upstream.objects.all())
    rules = list(WAFRule.objects.all())
    allow_ips = list(IpListEntry.objects.filter(list_type="allow").values_list("ip", flat=True))
    block_ips = list(IpListEntry.objects.filter(list_type="block").values_list("ip", flat=True))
    trusted = list(TrustedProxy.objects.all().values_list("cidr", flat=True))

    cfg = {
        "upstreams": [
            {
                "name": u.name,
                "url": u.url,
                "hosts": u.hosts,
                "path_prefixes": u.path_prefixes,
                "weight": u.weight,
                "healthcheck_path": u.healthcheck_path,
            } for u in upstreams
        ],
        "ip_allowlist": allow_ips or None,
        "ip_blocklist": block_ips or None,
        "trusted_proxies": trusted or None,
        "rules": [
            {
                "id": r.rule_id,
                "description": r.description,
                "target": r.target,
                "pattern": r.pattern,
                "score": r.score,
                "enabled": r.enabled,
            } for r in rules
        ] or None,
        "thresholds": {
            "allow": policy.allow_threshold,
            "challenge": policy.challenge_threshold,
            "block": policy.block_threshold,
        },
        "rate_limits": {"requests_per_minute": policy.requests_per_minute},
        "waf_settings": {
            "mode": policy.mode,
            "inspect_body": policy.inspect_body,
            "max_inspect_bytes": policy.max_inspect_bytes,
            "max_body_bytes": policy.max_body_bytes,
        },
    }
    return cfg

@transaction.atomic
def publish_current_config(user=None, comment=""):
    cfg = build_config_dict()

    # Validate with Pydantic (fast + matches your WAF schema style)
    PydanticConfig(**cfg)

    canonical = json.dumps(cfg, sort_keys=True, separators=(",", ":")).encode("utf-8")
    version_hash = hashlib.sha256(canonical).hexdigest()[:12]

    ConfigVersion.objects.filter(is_active=True).update(is_active=False)
    version = ConfigVersion.objects.create(
        version_hash=version_hash,
        created_by=user,
        comment=comment,
        is_active=True,
        config_json=cfg,
    )
    return version
