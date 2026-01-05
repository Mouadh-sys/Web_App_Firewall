from django.urls import path
from .views import overview, current_config

urlpatterns = [
    path("", overview, name="overview"),
    path("api/waf/config/current", current_config, name="current_config"),
]
