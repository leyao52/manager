"""API 路由表。"""
from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import (
    ClusterViewSet,
    CredentialRotationLogViewSet,
    DepartmentViewSet,
    HealthView,
    InstanceCredentialViewSet,
    InstanceStatDailyViewSet,
    InstanceViewSet,
    RequestTimingStatsView,
)

router = DefaultRouter()
router.register("departments", DepartmentViewSet, basename="department")
router.register("clusters", ClusterViewSet, basename="cluster")
router.register("instances", InstanceViewSet, basename="instance")
router.register("credentials", InstanceCredentialViewSet, basename="credential")
router.register("rotation-logs", CredentialRotationLogViewSet, basename="rotation-log")
router.register("daily-stats", InstanceStatDailyViewSet, basename="daily-stat")

urlpatterns = [
    path("health/", HealthView.as_view(), name="health"),
    path("request-timing/", RequestTimingStatsView.as_view(), name="request-timing"),
    path("", include(router.urls)),
]
