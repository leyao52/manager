"""DRF 序列化器。"""
from django.conf import settings
from django.utils import timezone
from rest_framework import serializers

from .models import (
    Cluster,
    CredentialRotationLog,
    Department,
    Instance,
    InstanceCredential,
    InstanceStatDaily,
)
from .services import generate_random_password, rotate_credential


class DepartmentSerializer(serializers.ModelSerializer):
    parent_name = serializers.SerializerMethodField()

    class Meta:
        model = Department
        fields = [
            "id",
            "name",
            "code",
            "parent",
            "parent_name",
            "description",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["created_at", "updated_at"]

    def get_parent_name(self, obj) -> str:
        return obj.parent.name if obj.parent_id else None

    def validate_parent(self, parent):
        if parent is None or self.instance is None:
            return parent
        if parent.pk == self.instance.pk:
            raise serializers.ValidationError("上级部门不能是自身")
        node = parent
        while node is not None:
            if node.pk == self.instance.pk:
                raise serializers.ValidationError("部门层级不能形成环")
            node = node.parent
        return parent


class ClusterSerializer(serializers.ModelSerializer):
    department_name = serializers.CharField(source="department.name", read_only=True)
    instance_count = serializers.SerializerMethodField()

    class Meta:
        model = Cluster
        fields = [
            "id",
            "name",
            "code",
            "department",
            "department_name",
            "db_type",
            "description",
            "instance_count",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["created_at", "updated_at"]

    def get_instance_count(self, obj) -> int:
        annotated = getattr(obj, "instance_count", None)
        return annotated if annotated is not None else obj.instances.count()


class InstanceSerializer(serializers.ModelSerializer):
    cluster_name = serializers.CharField(source="cluster.name", read_only=True)
    department_id = serializers.IntegerField(source="cluster.department_id", read_only=True)
    department_name = serializers.CharField(source="cluster.department.name", read_only=True)
    endpoint = serializers.CharField(read_only=True)
    has_credential = serializers.SerializerMethodField()

    class Meta:
        model = Instance
        fields = [
            "id",
            "name",
            "cluster",
            "cluster_name",
            "department_id",
            "department_name",
            "host",
            "port",
            "db_type",
            "role",
            "status",
            "description",
            "endpoint",
            "has_credential",
            "last_probe_at",
            "last_probe_ok",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["last_probe_at", "last_probe_ok", "created_at", "updated_at"]
        # 关掉 DRF 依据 UniqueConstraint 自动生成的 UniqueTogetherValidator，
        # 改由下方 validate() 返回更友好的 host 维度错误；数据库层约束仍然生效。
        validators = []

    def get_has_credential(self, obj) -> bool:
        try:
            obj.credential
        except InstanceCredential.DoesNotExist:
            return False
        return True

    def validate_port(self, value: int) -> int:
        if not 1 <= value <= 65535:
            raise serializers.ValidationError("端口必须在 1-65535 之间")
        return value

    def validate(self, attrs):
        cluster = attrs.get("cluster") or getattr(self.instance, "cluster", None)
        host = attrs.get("host") or getattr(self.instance, "host", None)
        port = attrs.get("port") or getattr(self.instance, "port", None)
        if cluster and host and port:
            duplicated = Instance.objects.filter(cluster=cluster, host=host, port=port)
            if self.instance is not None:
                duplicated = duplicated.exclude(pk=self.instance.pk)
            if duplicated.exists():
                raise serializers.ValidationError(
                    {"host": "同一集群下已存在相同 host:port 的实例"}
                )
        return attrs


class InstanceCredentialSerializer(serializers.ModelSerializer):
    instance_endpoint = serializers.CharField(source="instance.endpoint", read_only=True)
    # 仅用于写入，不会出现在响应中
    password = serializers.CharField(write_only=True, required=False, allow_blank=False)
    password_masked = serializers.CharField(read_only=True)
    rotation_due = serializers.SerializerMethodField()

    class Meta:
        model = InstanceCredential
        fields = [
            "id",
            "instance",
            "instance_endpoint",
            "username",
            "password",
            "password_masked",
            "password_version",
            "rotated_at",
            "rotate_interval_hours",
            "auto_rotate_enabled",
            "rotation_due",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["password_version", "rotated_at", "created_at", "updated_at"]

    def get_rotation_due(self, obj) -> bool:
        return obj.is_rotation_due()

    def create(self, validated_data):
        raw_password = validated_data.pop("password", None) or generate_random_password()
        validated_data.setdefault("rotate_interval_hours", settings.CREDENTIAL_ROTATE_INTERVAL_HOURS)
        credential = InstanceCredential(**validated_data)
        credential.set_password(raw_password)
        credential.rotated_at = timezone.now()
        credential.save()
        return credential

    def update(self, instance, validated_data):
        raw_password = validated_data.pop("password", None)
        for field, value in validated_data.items():
            setattr(instance, field, value)
        instance.save()
        if raw_password:
            rotate_credential(instance, new_password=raw_password)
        return instance


class CredentialRotationLogSerializer(serializers.ModelSerializer):
    instance_endpoint = serializers.CharField(source="instance.endpoint", read_only=True)

    class Meta:
        model = CredentialRotationLog
        fields = ["id", "credential", "instance", "instance_endpoint", "success", "message", "created_at"]
        read_only_fields = fields


class InstanceStatDailySerializer(serializers.ModelSerializer):
    department_name = serializers.CharField(source="department.name", read_only=True)
    department_code = serializers.CharField(source="department.code", read_only=True)
    # 部门级汇总行不含集群，必须显式返回 None：
    # CharField(source="cluster.name") 在 cluster 为空时会把整个字段跳过，导致响应里字段消失。
    cluster_name = serializers.SerializerMethodField()
    cluster_code = serializers.SerializerMethodField()

    def get_cluster_name(self, obj) -> str:
        return obj.cluster.name if obj.cluster_id else None

    def get_cluster_code(self, obj) -> str:
        return obj.cluster.code if obj.cluster_id else None

    class Meta:
        model = InstanceStatDaily
        fields = [
            "id",
            "stat_date",
            "department",
            "department_name",
            "department_code",
            "cluster",
            "cluster_name",
            "cluster_code",
            "instance_count",
            "online_count",
            "offline_count",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields
