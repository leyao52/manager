"""数据库实例管理系统 Django 配置。"""
import os
from pathlib import Path

from celery.schedules import crontab

BASE_DIR = Path(__file__).resolve().parent.parent


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_list(name: str, default: str = "") -> list:
    return [item.strip() for item in os.environ.get(name, default).split(",") if item.strip()]


# ---------------------------------------------------------------------------
# 基础配置
# ---------------------------------------------------------------------------
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "dev-only-insecure-secret-key-please-override")
DEBUG = _env_bool("DJANGO_DEBUG", True)
ALLOWED_HOSTS = _env_list("DJANGO_ALLOWED_HOSTS", "*")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "instances",
]

# 请求耗时中间件放在最外层，才能统计到包含其它中间件在内的完整耗时。
MIDDLEWARE = [
    "instances.middleware.RequestTimingMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

# ---------------------------------------------------------------------------
# 数据库：默认 sqlite，可通过环境变量切换到 PostgreSQL
# ---------------------------------------------------------------------------
if os.environ.get("DB_ENGINE", "sqlite").strip().lower() in {"postgres", "postgresql"}:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.environ.get("DB_NAME", "dbmgr"),
            "USER": os.environ.get("DB_USER", "postgres"),
            "PASSWORD": os.environ.get("DB_PASSWORD", "postgres"),
            "HOST": os.environ.get("DB_HOST", "127.0.0.1"),
            "PORT": os.environ.get("DB_PORT", "5432"),
            "CONN_MAX_AGE": _env_int("DB_CONN_MAX_AGE", 60),
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "zh-hans"
TIME_ZONE = os.environ.get("DJANGO_TIME_ZONE", "Asia/Shanghai")
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ---------------------------------------------------------------------------
# DRF
# ---------------------------------------------------------------------------
# 是否允许匿名访问 API。默认与 DEBUG 保持一致：开发环境开放，生产环境需登录。
API_ALLOW_ANONYMOUS = _env_bool("API_ALLOW_ANONYMOUS", DEBUG)

REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": (
        ["rest_framework.permissions.AllowAny"]
        if API_ALLOW_ANONYMOUS
        else ["rest_framework.permissions.IsAuthenticated"]
    ),
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": _env_int("API_PAGE_SIZE", 20),
    "DEFAULT_FILTER_BACKENDS": [
        "rest_framework.filters.SearchFilter",
        "rest_framework.filters.OrderingFilter",
    ],
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
        "rest_framework.authentication.BasicAuthentication",
    ],
}

# ---------------------------------------------------------------------------
# 业务参数
# ---------------------------------------------------------------------------
# 凭据加密密钥（Fernet key）。留空时由 SECRET_KEY 派生，便于本地开发。
CREDENTIAL_ENCRYPTION_KEY = os.environ.get("CREDENTIAL_ENCRYPTION_KEY", "")
# 密码轮换周期，需与 CELERY_BEAT_SCHEDULE 中的轮换频率保持一致
CREDENTIAL_ROTATE_INTERVAL_HOURS = _env_int("CREDENTIAL_ROTATE_INTERVAL_HOURS", 12)
CREDENTIAL_PASSWORD_LENGTH = _env_int("CREDENTIAL_PASSWORD_LENGTH", 24)
# TCP 端口探测超时
TCP_PROBE_TIMEOUT_SECONDS = _env_float("TCP_PROBE_TIMEOUT_SECONDS", 3.0)
# 慢请求告警阈值（毫秒）
REQUEST_TIMING_SLOW_THRESHOLD_MS = _env_float("REQUEST_TIMING_SLOW_THRESHOLD_MS", 500.0)

# ---------------------------------------------------------------------------
# Celery
# ---------------------------------------------------------------------------
CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL", "redis://127.0.0.1:6379/0")
CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", "redis://127.0.0.1:6379/1")
CELERY_TIMEZONE = TIME_ZONE
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_TIME_LIMIT = 60 * 30
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True

CELERY_BEAT_SCHEDULE = {
    # 每 12 小时（00:00、12:00）轮换一次实例密码
    "rotate-instance-passwords": {
        "task": "instances.tasks.rotate_instance_passwords",
        "schedule": crontab(minute=0, hour="*/12"),
    },
    # 每天 00:00 按部门 + 集群维度统计实例数量并落库
    "collect-daily-instance-stats": {
        "task": "instances.tasks.collect_daily_instance_stats",
        "schedule": crontab(minute=0, hour=0),
    },
    # 每 5 分钟刷新所有实例的端口可达状态
    "probe-all-instances": {
        "task": "instances.tasks.probe_all_instances",
        "schedule": crontab(minute="*/5"),
    },
}

# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------
LOG_LEVEL = os.environ.get("DJANGO_LOG_LEVEL", "INFO")

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "[{asctime}] {levelname} {name} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "loggers": {
        "django": {"handlers": ["console"], "level": LOG_LEVEL, "propagate": False},
        # 请求耗时统计
        "instances.request": {"handlers": ["console"], "level": LOG_LEVEL, "propagate": False},
        # 密码轮换 / 统计任务
        "instances.rotation": {"handlers": ["console"], "level": LOG_LEVEL, "propagate": False},
        "instances.stats": {"handlers": ["console"], "level": LOG_LEVEL, "propagate": False},
        "config.celery": {"handlers": ["console"], "level": LOG_LEVEL, "propagate": False},
    },
    "root": {"handlers": ["console"], "level": LOG_LEVEL},
}
