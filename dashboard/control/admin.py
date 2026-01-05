from django.contrib import admin
from django.utils import timezone
from .models import Upstream, WAFRule, Policy, IpListEntry, TrustedProxy, ConfigVersion
from .services import publish_current_config

@admin.register(Upstream)
class UpstreamAdmin(admin.ModelAdmin):
    list_display = ("name", "url", "weight")

@admin.register(WAFRule)
class WAFRuleAdmin(admin.ModelAdmin):
    list_display = ("rule_id", "target", "score", "enabled")
    list_filter = ("enabled", "target")
    search_fields = ("rule_id", "description", "pattern")

@admin.register(IpListEntry)
class IpListEntryAdmin(admin.ModelAdmin):
    list_display = ("list_type", "ip", "comment")
    list_filter = ("list_type",)
    search_fields = ("ip",)

@admin.register(TrustedProxy)
class TrustedProxyAdmin(admin.ModelAdmin):
    list_display = ("cidr",)

@admin.action(description="Publish current config (creates new active ConfigVersion)")
def publish_config_action(modeladmin, request, queryset):
    version = publish_current_config(user=request.user, comment="Published from admin")
    modeladmin.message_user(request, f"Published config version {version.version_hash}")

@admin.register(Policy)
class PolicyAdmin(admin.ModelAdmin):
    list_display = ("mode", "requests_per_minute", "block_threshold")
    actions = [publish_config_action]

@admin.register(ConfigVersion)
class ConfigVersionAdmin(admin.ModelAdmin):
    list_display = ("version_hash", "is_active", "created_at", "created_by")
    list_filter = ("is_active",)
