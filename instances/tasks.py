"""Celery 任务：密码轮换、每日统计、端口探测。"""
import logging

from celery import shared_task

from . import services
from .models import Instance

logger = logging.getLogger("instances.stats")


@shared_task(name="instances.tasks.rotate_instance_passwords")
def rotate_instance_passwords(instance_ids=None, force: bool = False) -> dict:
    """每 12 小时执行：为实例随机轮换密码并加密记录。

    :param instance_ids: 指定实例 ID 列表；为空表示全部实例
    :param force: True 时忽略轮换周期强制轮换
    """
    return services.rotate_passwords(instance_ids=instance_ids, force=force)


@shared_task(name="instances.tasks.collect_daily_instance_stats")
def collect_daily_instance_stats(stat_date=None) -> dict:
    """每天 00:00 执行：按部门 + 集群维度统计实例数量并写入数据库。"""
    return services.collect_instance_stats(stat_date=stat_date)


@shared_task(name="instances.tasks.probe_all_instances")
def probe_all_instances() -> dict:
    """探测全部实例的 TCP 端口可达性，并回写探测结果。"""
    reachable = unreachable = 0
    details = []
    for instance in Instance.objects.all().iterator():
        result = services.probe_instance(instance)
        if result.ok:
            reachable += 1
        else:
            unreachable += 1
        details.append(
            {
                "instance_id": instance.id,
                "endpoint": instance.endpoint,
                "reachable": result.ok,
                "latency_ms": result.latency_ms,
            }
        )
    summary = {"total": reachable + unreachable, "reachable": reachable, "unreachable": unreachable}
    logger.info("实例端口探测完成：%s", summary)
    summary["details"] = details
    return summary


@shared_task(name="instances.tasks.rotate_single_instance_password")
def rotate_single_instance_password(instance_id: int) -> dict:
    """轮换指定实例的密码（供外部按需触发）。"""
    return services.rotate_passwords(instance_ids=[instance_id], force=True)


__all__ = [
    "collect_daily_instance_stats",
    "probe_all_instances",
    "rotate_instance_passwords",
    "rotate_single_instance_password",
]
