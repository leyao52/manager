"""URL 路由。"""
from django.contrib import admin
from django.urls import include, path
from django.views.generic import RedirectView

urlpatterns = [
    # 根路径跳转到可浏览 API，避免直接访问域名根路径时撞 404
    path("", RedirectView.as_view(url="/api/", permanent=False)),
    path("admin/", admin.site.urls),
    path("api/", include("instances.urls")),
]
