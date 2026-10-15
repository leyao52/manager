"""请求耗时统计中间件：为每个请求记录耗时、写入响应头，并按路由聚合计数。"""
import logging
import threading
import time
from collections import defaultdict

from django.conf import settings

logger = logging.getLogger("instances.request")

_LOCK = threading.Lock()
# {(method, 路由模板): {"count": ..., "total_ms": ..., "max_ms": ..., "slow": ...}}
_COUNTERS = defaultdict(lambda: {"count": 0, "total_ms": 0.0, "max_ms": 0.0, "slow": 0})


def _record(route: str, duration_ms: float, slow_threshold_ms: float) -> None:
    with _LOCK:
        item = _COUNTERS[route]
        item["count"] += 1
        item["total_ms"] += duration_ms
        if duration_ms > item["max_ms"]:
            item["max_ms"] = duration_ms
        if duration_ms >= slow_threshold_ms:
            item["slow"] += 1


def request_timing_snapshot() -> list:
    """返回当前进程内按路由聚合的请求耗时统计。"""
    with _LOCK:
        snapshot = [
            {
                "route": route,
                "count": item["count"],
                "total_ms": round(item["total_ms"], 2),
                "avg_ms": round(item["total_ms"] / item["count"], 2) if item["count"] else 0.0,
                "max_ms": round(item["max_ms"], 2),
                "slow_count": item["slow"],
            }
            for route, item in _COUNTERS.items()
        ]
    snapshot.sort(key=lambda item: item["avg_ms"], reverse=True)
    return snapshot


def reset_request_timing() -> None:
    """清空统计（测试使用）。"""
    with _LOCK:
        _COUNTERS.clear()


class RequestTimingMiddleware:
    """统计每个请求的耗时。

    - 在响应头 `X-Request-Duration-Ms` 中返回本次请求耗时
    - 按 "METHOD 路由模板" 聚合次数 / 平均耗时 / 最大耗时
    - 超过 `REQUEST_TIMING_SLOW_THRESHOLD_MS` 的请求打 WARNING 日志
    """

    RESPONSE_HEADER = "X-Request-Duration-Ms"

    def __init__(self, get_response):
        self.get_response = get_response
        self.slow_threshold_ms = float(
            getattr(settings, "REQUEST_TIMING_SLOW_THRESHOLD_MS", 500.0)
        )

    def __call__(self, request):
        started = time.perf_counter()
        try:
            response = self.get_response(request)
        except Exception:
            self._record_exception(request, started)
            raise
        duration_ms = (time.perf_counter() - started) * 1000.0
        self._finalize(request, response, duration_ms)
        return response

    def _route_label(self, request) -> str:
        match = getattr(request, "resolver_match", None)
        route = getattr(match, "route", None) if match is not None else None
        return f"{request.method} /{route}" if route else f"{request.method} {request.path}"

    def _finalize(self, request, response, duration_ms: float) -> None:
        route = self._route_label(request)
        request.duration_ms = round(duration_ms, 2)
        try:
            response[self.RESPONSE_HEADER] = f"{duration_ms:.2f}"
        except Exception:  # 极少数响应对象不支持设置 header
            pass
        _record(route, duration_ms, self.slow_threshold_ms)
        if duration_ms >= self.slow_threshold_ms:
            logger.warning(
                "慢请求 %s 耗时 %.2fms（阈值 %.2fms）", route, duration_ms, self.slow_threshold_ms
            )
        else:
            logger.info("请求 %s 耗时 %.2fms", route, duration_ms)

    def _record_exception(self, request, started: float) -> None:
        duration_ms = (time.perf_counter() - started) * 1000.0
        route = self._route_label(request)
        _record(route, duration_ms, self.slow_threshold_ms)
        logger.error("请求处理异常 %s 耗时 %.2fms", route, duration_ms, exc_info=True)
