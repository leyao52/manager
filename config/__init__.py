"""确保 Django 启动时加载 Celery 应用，使 shared_task 生效。"""
from .celery import app as celery_app

__all__ = ("celery_app",)
