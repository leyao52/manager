"""DRF 视图：模型 CRUD、TCP 端口探测、密码轮换、每日统计。"""
from datetime import date

from django.db.models import Count
from django.db.models.deletion import ProtectedError
from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from . import services
from .crypto import CredentialCipherError
from .middleware import request_timing_snapshot
from .models import (
    Cluster,
    CredentialRotationLog,
    Department,
    Instance,
    InstanceCredential,
    InstanceStatDaily,
)
from .serializers import (
    ClusterSerializer,
    CredentialRotationLogSerializer,
    DepartmentSerializer,
    InstanceCredentialSerializer,
    InstanceSerializer,
    InstanceStatDailySerializer,
)


def _int_param(params, key: str):
    """安全解析整型查询参数，非法值返回 400 而不是 500。"""
    value = params.get(key)
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ValidationError({key: "必须为整数"})


class DepartmentViewSet(viewsets.ModelViewSet):
    """部门增删改查。"""

    queryset = Department.objects.select_related("parent")
    serializer_class = DepartmentSerializer
    search_fields = ["name", "code", "description"]
    ordering_fields = ["name", "code", "created_at", "id"]

    def perform_destroy(self, instance):
        try:
            instance.delete()
        except ProtectedError:
            raise ValidationError({"detail": "该部门下仍存在集群，请先删除或迁移集群"})


class ClusterViewSet(viewsets.ModelViewSet):
    """集群增删改查，支持按部门、数据库类型过滤。"""

    serializer_class = ClusterSerializer
    search_fields = ["name", "code", "description"]
    ordering_fields = ["name", "code", "created_at", "id"]

    def get_queryset(self):
        queryset = Cluster.objects.select_related("department").annotate(
            instance_count=Count("instances")
        )
        params = self.request.query_params
        department = _int_param(params, "department")
        if department is not None:
            queryset = queryset.filter(department_id=department)
        db_type = params.get("db_type")
        if db_type:
            queryset = queryset.filter(db_type=db_type)
        return queryset


class InstanceViewSet(viewsets.ModelViewSet):
    """实例增删改查，内置 TCP 端口可达性探测与密码轮换动作。"""

    serializer_class = InstanceSerializer
    search_fields = ["name", "host", "description"]
    ordering_fields = ["name", "created_at", "last_probe_at", "id"]

    def get_queryset(self):
        queryset = Instance.objects.select_related("cluster", "cluster__department")
        params = self.request.query_params
        cluster = _int_param(params, "cluster")
        if cluster is not None:
            queryset = queryset.filter(cluster_id=cluster)
        department = _int_param(params, "department")
        if department is not None:
            queryset = queryset.filter(cluster__department_id=department)
        db_type = params.get("db_type")
        if db_type:
            queryset = queryset.filter(db_type=db_type)
        status_value = params.get("status")
        if status_value:
            queryset = queryset.filter(status=status_value)
        reachable = params.get("reachable")
        if reachable:
            lowered = reachable.strip().lower()
            if lowered in {"1", "true", "yes"}:
                queryset = queryset.filter(last_probe_ok=True)
            elif lowered in {"0", "false", "no"}:
                queryset = queryset.filter(last_probe_ok=False)
            else:
                raise ValidationError({"reachable": "仅支持 true / false"})
        return queryset

    @action(detail=True, methods=["post"], url_path="tcp-probe")
    def tcp_probe(self, request, pk=None):
        """探测该实例的 TCP 端口是否可达，并回写探测结果。"""
        instance = self.get_object()
        timeout = request.data.get("timeout")
        try:
            result = services.probe_instance(instance, timeout=timeout)
        except (TypeError, ValueError) as exc:
            raise ValidationError({"detail": f"探测参数不合法：{exc}"})
        payload = result.as_dict()
        payload.update(
            {
                "instance": instance.id,
                "name": instance.name,
                "status": instance.status,
                "last_probe_at": instance.last_probe_at,
                "last_probe_ok": instance.last_probe_ok,
            }
        )
        return Response(payload)

    @action(detail=False, methods=["post"], url_path="tcp-probe-all")
    def tcp_probe_all(self, request):
        """批量探测（同样支持列表接口的过滤与搜索参数）。"""
        reachable = unreachable = 0
        results = []
        for instance in self.filter_queryset(self.get_queryset()).iterator():
            result = services.probe_instance(instance)
            if result.ok:
                reachable += 1
            else:
                unreachable += 1
            row = result.as_dict()
            row["instance"] = instance.id
            row["name"] = instance.name
            results.append(row)
        return Response(
            {
                "total": reachable + unreachable,
                "reachable": reachable,
                "unreachable": unreachable,
                "results": results,
            }
        )

    @action(detail=True, methods=["post"], url_path="rotate-password")
    def rotate_password(self, request, pk=None):
        """立即随机轮换该实例的密码。"""
        instance = self.get_object()
        try:
            credential = instance.credential
        except InstanceCredential.DoesNotExist:
            return Response(
                {"detail": "该实例尚未配置账号密码凭据"}, status=status.HTTP_404_NOT_FOUND
            )
        log = services.rotate_credential(credential)
        return Response(
            {
                "instance": instance.id,
                "username": credential.username,
                "password": log.get_new_password(),
                "password_version": credential.password_version,
                "rotated_at": credential.rotated_at,
                "notice": "明文密码仅在本次响应中返回，请立即保存",
            }
        )


class InstanceCredentialViewSet(viewsets.ModelViewSet):
    """实例账号密码管理（密码加密存储，默认不返回明文）。"""

    serializer_class = InstanceCredentialSerializer
    search_fields = ["username", "instance__name", "instance__host"]
    ordering_fields = ["username", "rotated_at", "created_at", "id"]

    def get_queryset(self):
        queryset = InstanceCredential.objects.select_related("instance")
        instance = _int_param(self.request.query_params, "instance")
        if instance is not None:
            queryset = queryset.filter(instance_id=instance)
        return queryset

    @action(detail=True, methods=["get"], url_path="reveal")
    def reveal(self, request, pk=None):
        """显式读取明文密码。"""
        credential = self.get_object()
        try:
            password = credential.get_password()
        except CredentialCipherError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_409_CONFLICT)
        return Response(
            {
                "id": credential.id,
                "instance": credential.instance_id,
                "username": credential.username,
                "password": password,
                "password_version": credential.password_version,
                "rotated_at": credential.rotated_at,
            }
        )

    @action(detail=True, methods=["post"], url_path="rotate")
    def rotate(self, request, pk=None):
        """立即随机轮换密码并返回一次明文。"""
        credential = self.get_object()
        log = services.rotate_credential(credential)
        return Response(
            {
                "id": credential.id,
                "instance": credential.instance_id,
                "username": credential.username,
                "password": log.get_new_password(),
                "password_version": credential.password_version,
                "rotated_at": credential.rotated_at,
                "notice": "明文密码仅在本次响应中返回，请立即保存",
            }
        )

    @action(detail=True, methods=["get"], url_path="rotation-logs")
    def rotation_logs(self, request, pk=None):
        """查看该凭据的密码轮换历史。"""
        credential = self.get_object()
        logs = credential.rotation_logs.select_related("instance")[:50]
        return Response(CredentialRotationLogSerializer(logs, many=True).data)


class CredentialRotationLogViewSet(viewsets.ReadOnlyModelViewSet):
    """密码轮换审计日志（只读）。"""

    queryset = CredentialRotationLog.objects.select_related("instance")
    serializer_class = CredentialRotationLogSerializer
    ordering_fields = ["created_at", "id"]

    def get_queryset(self):
        queryset = super().get_queryset()
        params = self.request.query_params
        instance = _int_param(params, "instance")
        if instance is not None:
            queryset = queryset.filter(instance_id=instance)
        credential = _int_param(params, "credential")
        if credential is not None:
            queryset = queryset.filter(credential_id=credential)
        success = params.get("success")
        if success:
            lowered = success.strip().lower()
            if lowered in {"1", "true", "yes"}:
                queryset = queryset.filter(success=True)
            elif lowered in {"0", "false", "no"}:
                queryset = queryset.filter(success=False)
        return queryset


class InstanceStatDailyViewSet(viewsets.ReadOnlyModelViewSet):
    """每日实例统计查询，支持手动触发统计。"""

    queryset = InstanceStatDaily.objects.select_related("department", "cluster")
    serializer_class = InstanceStatDailySerializer
    ordering_fields = ["stat_date", "instance_count", "id"]

    def get_queryset(self):
        queryset = super().get_queryset()
        params = self.request.query_params
        stat_date = params.get("stat_date")
        if stat_date:
            queryset = queryset.filter(stat_date=self._parse_date(stat_date, "stat_date"))
        start = params.get("start_date")
        if start:
            queryset = queryset.filter(stat_date__gte=self._parse_date(start, "start_date"))
        end = params.get("end_date")
        if end:
            queryset = queryset.filter(stat_date__lte=self._parse_date(end, "end_date"))
        department = _int_param(params, "department")
        if department is not None:
            queryset = queryset.filter(department_id=department)
        cluster = _int_param(params, "cluster")
        if cluster is not None:
            queryset = queryset.filter(cluster_id=cluster)
        return queryset

    @staticmethod
    def _parse_date(value: str, field: str) -> date:
        try:
            return date.fromisoformat(str(value).strip())
        except ValueError:
            raise ValidationError({field: "需为 YYYY-MM-DD 格式"})

    @action(detail=False, methods=["post"], url_path="collect")
    def collect(self, request):
        """手动触发按部门 + 集群维度的实例统计落库（等价于每日 00:00 定时任务）。"""
        try:
            result = services.collect_instance_stats(request.data.get("stat_date"))
        except ValueError as exc:
            raise ValidationError({"stat_date": str(exc)})
        return Response(result, status=status.HTTP_201_CREATED)


class RequestTimingStatsView(APIView):
    """查看当前进程内按路由聚合的请求耗时统计。"""

    def get(self, request):
        return Response({"counters": request_timing_snapshot()})


class HealthView(APIView):
    """健康检查。"""

    def get(self, request):
        return Response({"status": "ok", "server_time": timezone.now().isoformat()})
