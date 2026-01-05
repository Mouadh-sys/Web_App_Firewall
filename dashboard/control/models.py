from django.db import models
from django.conf import settings

class Upstream(models.Model):
    name = models.CharField(max_length=64, unique=True)
    url = models.URLField()
    hosts = models.JSONField(blank=True, null=True)         # list[str]
    path_prefixes = models.JSONField(blank=True, null=True) # list[str]
    weight = models.IntegerField(default=1)
    healthcheck_path = models.CharField(max_length=256, blank=True, null=True)

    def __str__(self):
        return self.name

class WAFRule(models.Model):
    TARGET_CHOICES = [("path","path"), ("path_raw","path_raw"), ("query","query"), ("headers","headers"), ("body","body")]

    rule_id = models.CharField(max_length=64, unique=True)
    description = models.CharField(max_length=256)
    target = models.CharField(max_length=16, choices=TARGET_CHOICES, default="path")
    pattern = models.TextField()
    score = models.IntegerField(default=0)
    enabled = models.BooleanField(default=True)

    def __str__(self):
        return self.rule_id

class Policy(models.Model):
    # singleton-ish (you can enforce 1 row later)
    mode = models.CharField(max_length=16, default="block")  # monitor/block
    inspect_body = models.BooleanField(default=False)
    max_inspect_bytes = models.IntegerField(default=10_000)
    max_body_bytes = models.IntegerField(default=1_000_000)

    allow_threshold = models.IntegerField(default=5)
    challenge_threshold = models.IntegerField(default=6)
    block_threshold = models.IntegerField(default=10)

    requests_per_minute = models.IntegerField(default=60)

    def __str__(self):
        return f"Policy({self.mode})"

class IpListEntry(models.Model):
    LIST_CHOICES = [("allow","allow"), ("block","block")]
    list_type = models.CharField(max_length=8, choices=LIST_CHOICES)
    ip = models.CharField(max_length=64)  # keep simple (IP or CIDR if you want)
    comment = models.CharField(max_length=256, blank=True, null=True)

    def __str__(self):
        return f"{self.list_type}:{self.ip}"

class TrustedProxy(models.Model):
    cidr = models.CharField(max_length=64, unique=True)
    def __str__(self):
        return self.cidr

class ConfigVersion(models.Model):
    version_hash = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True
    )
    comment = models.CharField(max_length=256, blank=True, null=True)
    is_active = models.BooleanField(default=False)
    config_json = models.JSONField()

    def __str__(self):
        return self.version_hash
