from django.http import JsonResponse, HttpResponse
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from .models import ConfigVersion

def _require_token(request):
    expected = getattr(settings, "WAF_API_TOKEN", "")
    auth = request.headers.get("Authorization", "")
    return auth == f"Bearer {expected}"

def current_config(request):
    if not _require_token(request):
        return JsonResponse({"detail": "unauthorized"}, status=401)

    version = ConfigVersion.objects.filter(is_active=True).first()
    if not version:
        return JsonResponse({"detail": "no active config"}, status=404)

    etag = version.version_hash
    if request.headers.get("If-None-Match") == etag:
        return HttpResponse(status=304)

    resp = JsonResponse(version.config_json)
    resp["ETag"] = etag
    resp["Cache-Control"] = "no-cache"
    return resp

@login_required
def overview(request):
    # Put your panel iframe URLs here after you create the Grafana dashboard (Step 11)
    panels = getattr(settings, "GRAFANA_EMBED_PANELS", [])
    return render(request, "overview.html", {"panels": panels})
