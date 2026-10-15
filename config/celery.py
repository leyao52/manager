"""Celery 应用配置与定时任务调度。"""
import os

from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

app = Celery("dbmgr")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()
