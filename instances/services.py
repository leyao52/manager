"""业务服务层：随机密码生成、TCP 端口探测、密码轮换、实例数量统计。"""
import logging
import secrets
import socket
import string
import time
from dataclasses import dataclass
from datetime import date, datetime

from django.conf import settings
from django.db import transaction
from django.db.models import Count
from django.utils import timezone

from .models import (
    Cluster,
    CredentialRotationLog,
    Instance,
    InstanceCredential,
    InstanceStatDaily,
    InstanceStatus,
)

logger = logging.getLogger("instances.rotation")

PASSWORD_ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
SPECIAL_CHARS = "!@#$%^&*()-_=+"


class PasswordGenerationError(RuntimeError):
    """无法生成符合复杂度要求的随机密码。"""


def generate_random_password(length: int = None) -> str:
    """生成包含大小写字母、数字与特殊字符的随机密码。"""
    length = max(int(length or settings.CREDENTIAL_PASSWORD_LENGTH), 12)
    for _ in range(100):
        password = "".join(secrets.choice(PASSWORD_ALPHABET) for _ in range(length))
        if (
            any(c.islower() for c in password)
            and any(c.isupper() for c in password)
            and any(c.isdigit() for c in password)
            and any(c in SPECIAL_CHARS for c in password)
        ):
            return password
    raise PasswordGenerationError("无法生成满足复杂度要求的随机密码，请调整密码长度")


# ---------------------------------------------------------------------------
# TCP 端口探测
# ---------------------------------------------------------------------------
@dataclass
class ProbeResult:
    """单个实例的 TCP 可达性探测结果。"""

    host: str
    port: int
    ok: bool
    latency_ms: float
    error: str = ""

    def as_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "reachable": self.ok,
            "latency_ms": self.latency_ms,
            "error": self.error,
        }


def probe_tcp(host: str, port: int, timeout: float = None) -> ProbeResult:
    """探测 host:port 是否 TCP 可达（建立 TCP 连接即视为可达）。"""
    if not host:
        raise ValueError("host 不能为空")
    port = int(port)
    if not 1 <= port <= 65535:
        raise ValueError("端口必须在 1-65535 之间")
    timeout = float(settings.TCP_PROBE_TIMEOUT_SECONDS if timeout is None else timeout)
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except OSError as exc:
        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        return ProbeResult(
            host=host,
            port=port,
            ok=False,
            latency_ms=latency_ms,
            error=f"{type(exc).__name__}: {exc}",
        )
    latency_ms = round((time.perf_counter() - started) * 1000, 2)
    return ProbeResult(host=host, port=port, ok=True, latency_ms=latency_ms)


def probe_instance(instance: Instance, timeout: float = None, save: bool = True) -> ProbeResult:
    """探测实例端口可达性，并把结果回写到实例（在线/离线状态同步更新）。"""
    result = probe_tcp(instance.host, instance.port, timeout=timeout)
    if save:
        update_fields = ["last_probe_at", "last_probe_ok", "updated_at"]
        instance.last_probe_at = timezone.now()
        instance.last_probe_ok = result.ok
        # 维护中的实例不因探测结果被改写为在线
        if instance.status == InstanceStatus.MAINTENANCE:
            pass
        elif result.ok and instance.status != InstanceStatus.ONLINE:
            instance.status = InstanceStatus.ONLINE
            update_fields.append("status")
        elif not result.ok and instance.status != InstanceStatus.OFFLINE:
            instance.status = InstanceStatus.OFFLINE
            update_fields.append("status")
        instance.save(update_fields=update_fields)
    return result


# ---------------------------------------------------------------------------
# 密码轮换
# ---------------------------------------------------------------------------
def rotate_credential(credential: InstanceCredential, new_password: str = None) -> CredentialRotationLog:
    """轮换单个实例密码：生成随机密码 -> 加密入库 -> 写入审计记录。"""
    raw_password = new_password or generate_random_password()
    previous_ciphertext = credential.password_ciphertext

    credential.set_password(raw_password)
    credential.password_version += 1
    credential.rotated_at = timezone.now()
    credential.save(
        update_fields=["password_ciphertext", "password_version", "rotated_at", "updated_at"]
    )

    log = CredentialRotationLog.objects.create(
        credential=credential,
        instance_id=credential.instance_id,
        old_password_ciphertext=previous_ciphertext,
        new_password_ciphertext=credential.password_ciphertext,
        success=True,
        message=f"密码已随机轮换至 v{credential.password_version}",
    )
    logger.info(
        "实例 %s 密码轮换成功，当前版本 v%s", credential.instance.endpoint, credential.password_version
    )
    return log


def rotate_passwords(instance_ids=None, force: bool = False, now: datetime = None) -> dict:
    """批量轮换密码。默认只轮换已到期（超过轮换周期）的凭据。

    :param instance_ids: 仅轮换这些实例，None 表示全部
    :param force: True 表示忽略轮换周期与 auto_rotate_enabled 开关，强制轮换
    """
    queryset = InstanceCredential.objects.select_related("instance").order_by("id")
    if instance_ids:
        queryset = queryset.filter(instance_id__in=list(instance_ids))
    now = now or timezone.now()

    total = success = failed = skipped = 0
    for credential in queryset.iterator():
        if not force and not credential.is_rotation_due(now=now):
            skipped += 1
            continue
        total += 1
        try:
            rotate_credential(credential)
            success += 1
        except Exception as exc:  # noqa: BLE001 保证单条失败不影响整体轮换
            failed += 1
            CredentialRotationLog.objects.create(
                credential=credential,
                instance_id=credential.instance_id,
                old_password_ciphertext=credential.password_ciphertext,
                new_password_ciphertext="",
                success=False,
                message=f"{type(exc).__name__}: {exc}"[:255],
            )
            logger.exception("实例 %s 密码轮换失败", credential.instance.endpoint)

    result = {"total": total, "success": success, "failed": failed, "skipped": skipped}
    logger.info("密码轮换任务结束：%s", result)
    return result


# ---------------------------------------------------------------------------
# 实例数量统计
# ---------------------------------------------------------------------------
def _normalize_stat_date(value) -> date:
    if value is None:
        return timezone.localdate()
    if isinstance(value, datetime):
        return timezone.localtime(value).date() if timezone.is_aware(value) else value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value.strip())
        except ValueError as exc:
            raise ValueError("stat_date 需为 YYYY-MM-DD 格式") from exc
    raise ValueError("stat_date 需为 YYYY-MM-DD 格式的字符串或 date 对象")


def collect_instance_stats(stat_date=None) -> dict:
    """按 部门 + 集群 维度统计实例数量，并写入 InstanceStatDaily（幂等，可重复执行）。"""
    stat_date = _normalize_stat_date(stat_date)

    clusters = list(Cluster.objects.values("id", "department_id").order_by("id"))
    # 注意：必须显式 order_by() 清除模型 Meta.ordering，否则排序字段会进入 GROUP BY，
    # 导致按 cluster_id 分组统计数量时结果错误（Django 官方文档中的经典陷阱）。
    total_map = dict(
        Instance.objects.values_list("cluster_id").annotate(count=Count("id")).order_by()
    )
    online_map = dict(
        Instance.objects.filter(status=InstanceStatus.ONLINE)
        .values_list("cluster_id")
        .annotate(count=Count("id"))
        .order_by()
    )
    offline_map = dict(
        Instance.objects.filter(status=InstanceStatus.OFFLINE)
        .values_list("cluster_id")
        .annotate(count=Count("id"))
        .order_by()
    )

    rows = 0
    with transaction.atomic():
        for cluster in clusters:
            cluster_id = cluster["id"]
            instance_count = total_map.get(cluster_id, 0)
            InstanceStatDaily.objects.update_or_create(
                stat_date=stat_date,
                department_id=cluster["department_id"],
                cluster_id=cluster_id,
                defaults={
                    "instance_count": instance_count,
                    "online_count": online_map.get(cluster_id, 0),
                    "offline_count": offline_map.get(cluster_id, 0),
                },
            )
            rows += 1

    logger.info("实例统计落库完成：date=%s，部门/集群维度共 %s 行", stat_date, rows)
    return {
        "stat_date": stat_date.isoformat(),
        "rows": rows,
        "instance_total": sum(total_map.values()),
    }
