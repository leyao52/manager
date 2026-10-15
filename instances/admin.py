"""Django Admin 配置。"""
from django.contrib import admin
from django.utils import timezone

from .models import (
    Cluster,
    CredentialRotationLog,
    Department,
    Instance,
    InstanceCredential,
    InstanceStatDaily,
)
from .services import generate_random_password


@admin.register(Department)
class DepartmentAdmin(admin.ModelAdmin):
    list_display = ("name", "code", "parent", "created_at")
    search_fields = ("name", "code")
    ordering = ("name",)


@admin.register(Cluster)
class ClusterAdmin(admin.ModelAdmin):
    list_display = ("name", "code", "department", "db_type", "created_at")
    list_filter = ("db_type", "department")
    search_fields = ("name", "code")
    ordering = ("name",)


@admin.register(Instance)
class InstanceAdmin(admin.ModelAdmin):
    list_display = ("name", "endpoint", "cluster", "db_type", "role", "status", "last_probe_ok")
    list_filter = ("status", "db_type", "role", "cluster__department")
    search_fields = ("name", "host")
    ordering = ("name",)
    readonly_fields = ("last_probe_at", "last_probe_ok", "created_at", "updated_at")

    @admin.display(description="连接地址")
    def endpoint(self, obj):
        return obj.endpoint


@admin.register(InstanceCredential)
class InstanceCredentialAdmin(admin.ModelAdmin):
    list_display = ("instance", "username", "password_version", "rotated_at", "rotate_interval_hours")
    search_fields = ("username", "instance__name", "instance__host")
    readonly_fields = ("password_ciphertext", "password_version", "rotated_at", "created_at", "updated_at")

    def save_model(self, request, obj, form, change):
        # 新建时未提供密码则自动生成随机密码，保证密文字段不为空
        if not obj.password_ciphertext:
            obj.set_password(generate_random_password())
            obj.rotated_at = timezone.now()
        super().save_model(request, obj, form, change)


@admin.register(CredentialRotationLog)
class CredentialRotationLogAdmin(admin.ModelAdmin):
    list_display = ("instance", "success", "message", "created_at")
    list_filter = ("success",)
    readonly_fields = (
        "credential",
        "instance",
        "old_password_ciphertext",
        "new_password_ciphertext",
        "success",
        "message",
        "created_at",
    )

    def has_add_permission(self, request):
        return False


@admin.register(InstanceStatDaily)
class InstanceStatDailyAdmin(admin.ModelAdmin):
    list_display = (
        "stat_date",
        "department",
        "cluster",
        "instance_count",
        "online_count",
        "offline_count",
    )
    list_filter = ("stat_date", "department")
    ordering = ("-stat_date",)
