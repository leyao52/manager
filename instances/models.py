"""实例管理系统的核心数据模型：部门、集群、实例、凭据、轮换审计、每日统计。"""
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone

from .crypto import CredentialCipherError, decrypt, encrypt


class DbType(models.TextChoices):
    MYSQL = "mysql", "MySQL"
    POSTGRESQL = "postgresql", "PostgreSQL"
    REDIS = "redis", "Redis"
    MONGODB = "mongodb", "MongoDB"
    ORACLE = "oracle", "Oracle"
    SQLSERVER = "sqlserver", "SQL Server"
    OTHER = "other", "其它"


class InstanceRole(models.TextChoices):
    MASTER = "master", "主库"
    SLAVE = "slave", "从库"
    PROXY = "proxy", "代理"
    STANDALONE = "standalone", "单机"


class InstanceStatus(models.TextChoices):
    ONLINE = "online", "在线"
    OFFLINE = "offline", "离线"
    MAINTENANCE = "maintenance", "维护中"


class TimeStampedModel(models.Model):
    """带创建/更新时间的抽象基类。"""

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class Department(TimeStampedModel):
    """部门，支持上下级树状结构。"""

    name = models.CharField(max_length=128, unique=True)
    code = models.CharField(max_length=64, unique=True)
    parent = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="children",
    )
    description = models.TextField(blank=True, default="")

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return f"{self.name}({self.code})"


class Cluster(TimeStampedModel):
    """数据库集群，归属于某个部门。"""

    name = models.CharField(max_length=128, unique=True)
    code = models.CharField(max_length=64, unique=True)
    department = models.ForeignKey(
        Department,
        on_delete=models.PROTECT,
        related_name="clusters",
    )
    db_type = models.CharField(max_length=32, choices=DbType.choices, default=DbType.MYSQL)
    description = models.TextField(blank=True, default="")

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return f"{self.name}({self.code})"


class Instance(TimeStampedModel):
    """数据库实例。"""

    name = models.CharField(max_length=128, unique=True)
    cluster = models.ForeignKey(Cluster, on_delete=models.CASCADE, related_name="instances")
    host = models.CharField(max_length=255)
    port = models.PositiveIntegerField()
    db_type = models.CharField(max_length=32, choices=DbType.choices, default=DbType.MYSQL)
    role = models.CharField(
        max_length=32, choices=InstanceRole.choices, default=InstanceRole.STANDALONE
    )
    status = models.CharField(
        max_length=32, choices=InstanceStatus.choices, default=InstanceStatus.ONLINE
    )
    description = models.TextField(blank=True, default="")
    # 最近一次 TCP 端口探测结果
    last_probe_at = models.DateTimeField(null=True, blank=True)
    last_probe_ok = models.BooleanField(null=True, blank=True)

    class Meta:
        ordering = ["name"]
        constraints = [
            models.UniqueConstraint(
                fields=["cluster", "host", "port"], name="uniq_instance_cluster_endpoint"
            )
        ]

    def __str__(self) -> str:
        return f"{self.name}@{self.host}:{self.port}"

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"


class InstanceCredential(TimeStampedModel):
    """实例的账号密码，密码以密文形式落库。"""

    instance = models.OneToOneField(
        Instance, on_delete=models.CASCADE, related_name="credential"
    )
    username = models.CharField(max_length=128, default="root")
    password_ciphertext = models.TextField()
    password_version = models.PositiveIntegerField(default=1)
    rotated_at = models.DateTimeField(null=True, blank=True)
    rotate_interval_hours = models.PositiveIntegerField(default=12)
    # 自动轮换开关：关闭后定时任务不再轮换该凭据，手动轮换接口不受影响
    auto_rotate_enabled = models.BooleanField(default=True)

    class Meta:
        ordering = ["id"]

    def __str__(self) -> str:
        return f"{self.instance.endpoint} 凭据(v{self.password_version})"

    # -- 密码读写 ---------------------------------------------------------
    def set_password(self, raw_password: str) -> None:
        self.password_ciphertext = encrypt(raw_password)

    def get_password(self) -> str:
        return decrypt(self.password_ciphertext)

    def try_get_password(self):
        """解密失败时返回 None，避免因单条密钥异常中断批量任务。"""
        try:
            return self.get_password()
        except CredentialCipherError:
            return None

    @property
    def password_masked(self) -> str:
        return "********"

    # -- 轮换周期 ---------------------------------------------------------
    def is_rotation_due(self, now=None) -> bool:
        """从未轮换过，或已超过 rotate_interval_hours 未轮换，则需要轮换。

        关闭 auto_rotate_enabled 的凭据不参与自动轮换，恒返回 False；
        手动调用轮换接口（rotate_credential）不受该开关限制。
        """
        if not self.auto_rotate_enabled:
            return False
        if self.rotated_at is None:
            return True
        now = now or timezone.now()
        # 用 is None 判断而非 or：0 是合法周期（表示立即到期），
        # 若写成 `self.rotate_interval_hours or 默认值`，0 会被误当成未设置而回退到默认周期。
        interval = (
            self.rotate_interval_hours
            if self.rotate_interval_hours is not None
            else settings.CREDENTIAL_ROTATE_INTERVAL_HOURS
        )
        return self.rotated_at + timedelta(hours=interval) <= now


class CredentialRotationLog(models.Model):
    """密码轮换审计记录，新旧密码均以密文留存。"""

    credential = models.ForeignKey(
        InstanceCredential, on_delete=models.CASCADE, related_name="rotation_logs"
    )
    instance = models.ForeignKey(
        Instance, on_delete=models.CASCADE, related_name="rotation_logs"
    )
    old_password_ciphertext = models.TextField(blank=True, default="")
    new_password_ciphertext = models.TextField(blank=True, default="")
    success = models.BooleanField(default=True)
    message = models.CharField(max_length=255, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"轮换 {self.instance.endpoint} @ {self.created_at:%Y-%m-%d %H:%M:%S}"

    def get_old_password(self):
        return decrypt(self.old_password_ciphertext) if self.old_password_ciphertext else None

    def get_new_password(self):
        return decrypt(self.new_password_ciphertext) if self.new_password_ciphertext else None


class InstanceStatDaily(models.Model):
    """按 日期 + 部门 + 集群 维度聚合的实例数量快照。

    cluster 为 NULL 的行是部门级汇总行，数值等于该部门下所有集群行之和。
    """

    stat_date = models.DateField()
    department = models.ForeignKey(
        Department, on_delete=models.CASCADE, related_name="daily_stats"
    )
    # cluster 为空表示该行是「部门级汇总行」，即该部门下所有集群的合计
    cluster = models.ForeignKey(
        Cluster, null=True, blank=True, on_delete=models.CASCADE, related_name="daily_stats"
    )
    instance_count = models.PositiveIntegerField(default=0)
    online_count = models.PositiveIntegerField(default=0)
    offline_count = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-stat_date"]
        constraints = [
            models.UniqueConstraint(
                fields=["stat_date", "department", "cluster"],
                name="uniq_daily_stat_dept_cluster",
            )
        ]

    def __str__(self) -> str:
        scope = self.cluster.code if self.cluster_id else "部门汇总"
        return f"{self.stat_date} {self.department.code}/{scope}: {self.instance_count}"
