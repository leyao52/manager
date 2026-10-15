"""单元测试与接口测试：加解密、TCP 探测、密码轮换、统计、中间件、REST 接口。"""
import socket
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from . import services
from .crypto import CredentialCipherError, decrypt, encrypt, generate_encryption_key
from .middleware import request_timing_snapshot, reset_request_timing
from .models import (
    Cluster,
    CredentialRotationLog,
    Department,
    Instance,
    InstanceCredential,
    InstanceStatDaily,
    InstanceStatus,
)
from .tasks import collect_daily_instance_stats, rotate_instance_passwords, probe_all_instances


# ---------------------------------------------------------------------------
# 测试辅助
# ---------------------------------------------------------------------------
def build_department(name="平台研发部", code="PLATFORM"):
    return Department.objects.create(name=name, code=code)


def build_cluster(department, name="交易集群", code="trade"):
    return Cluster.objects.create(name=name, code=code, department=department)


def build_instance(cluster, name="trade-01", host="127.0.0.1", port=3306, status=InstanceStatus.ONLINE):
    return Instance.objects.create(
        name=name, cluster=cluster, host=host, port=port, status=status
    )


def build_credential(instance, username="app", password="Initial-Passw0rd!"):
    credential = InstanceCredential(instance=instance, username=username)
    credential.set_password(password)
    credential.save()
    return credential


class LocalTcpServerMixin:
    """在本地监听一个随机端口，用于 TCP 可达性测试。"""

    def setUpLocalServer(self):
        self._servers = []
        self.addCleanup(self.stop_servers)

    def start_server(self) -> int:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(5)
        self._servers.append(server)
        return server.getsockname()[1]

    def stop_servers(self):
        while self._servers:
            server = self._servers.pop()
            try:
                server.close()
            except OSError:  # pragma: no cover
                pass

    @staticmethod
    def find_closed_port() -> int:
        """申请一个空闲端口后立即释放，用于构造不可达的场景。"""
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        return port


# ---------------------------------------------------------------------------
# 加解密 / 密码生成
# ---------------------------------------------------------------------------
class CryptoServiceTests(TestCase):
    def test_encrypt_decrypt_roundtrip(self):
        plaintext = "S3cret!Passw0rd"
        ciphertext = encrypt(plaintext)
        self.assertNotIn(plaintext, ciphertext)
        self.assertEqual(decrypt(ciphertext), plaintext)

    def test_decrypt_with_other_key_raises(self):
        ciphertext = encrypt("abc123")
        with self.settings(CREDENTIAL_ENCRYPTION_KEY=generate_encryption_key()):
            with self.assertRaises(CredentialCipherError):
                decrypt(ciphertext)

    def test_credential_password_is_encrypted_at_rest(self):
        instance = build_instance(build_cluster(build_department()))
        credential = build_credential(instance, password="Plain-Text-Pwd!")
        credential.refresh_from_db()
        self.assertNotIn("Plain-Text-Pwd!", credential.password_ciphertext)
        self.assertEqual(credential.get_password(), "Plain-Text-Pwd!")
        self.assertEqual(credential.password_masked, "********")

    def test_generate_random_password(self):
        password = services.generate_random_password(16)
        self.assertEqual(len(password), 16)
        self.assertTrue(any(c.islower() for c in password))
        self.assertTrue(any(c.isupper() for c in password))
        self.assertTrue(any(c.isdigit() for c in password))
        self.assertTrue(any(c in services.SPECIAL_CHARS for c in password))
        self.assertNotEqual(services.generate_random_password(), services.generate_random_password())


# ---------------------------------------------------------------------------
# TCP 端口探测
# ---------------------------------------------------------------------------
class TcpProbeTests(LocalTcpServerMixin, TestCase):
    def setUp(self):
        self.setUpLocalServer()
        self.department = build_department()
        self.cluster = build_cluster(self.department)

    def test_probe_reachable_port(self):
        port = self.start_server()
        result = services.probe_tcp("127.0.0.1", port, timeout=2)
        self.assertTrue(result.ok)
        self.assertEqual(result.error, "")
        self.assertGreaterEqual(result.latency_ms, 0)

    def test_probe_unreachable_port(self):
        port = self.start_server()
        self.stop_servers()  # 关闭监听后端口不可达
        result = services.probe_tcp("127.0.0.1", port, timeout=1)
        self.assertFalse(result.ok)
        self.assertTrue(result.error)

    def test_probe_invalid_port(self):
        with self.assertRaises(ValueError):
            services.probe_tcp("127.0.0.1", 70000)

    def test_probe_instance_writes_back_result(self):
        port = self.start_server()
        instance = build_instance(
            self.cluster, name="probe-ok", port=port, status=InstanceStatus.OFFLINE
        )
        result = services.probe_instance(instance)
        self.assertTrue(result.ok)
        instance.refresh_from_db()
        self.assertTrue(instance.last_probe_ok)
        self.assertIsNotNone(instance.last_probe_at)
        # 探测成功后将离线状态修正为在线
        self.assertEqual(instance.status, InstanceStatus.ONLINE)

    def test_probe_instance_keeps_maintenance_status(self):
        port = self.start_server()
        instance = build_instance(
            self.cluster, name="probe-maintenance", port=port, status=InstanceStatus.MAINTENANCE
        )
        services.probe_instance(instance)
        instance.refresh_from_db()
        self.assertEqual(instance.status, InstanceStatus.MAINTENANCE)

    def test_probe_all_instances_task(self):
        port = self.start_server()
        build_instance(self.cluster, name="up", port=port)
        build_instance(self.cluster, name="down", port=self.find_closed_port())
        result = probe_all_instances.run()
        self.assertEqual(result["total"], 2)
        self.assertEqual(result["reachable"], 1)
        self.assertEqual(result["unreachable"], 1)


# ---------------------------------------------------------------------------
# 密码轮换
# ---------------------------------------------------------------------------
class PasswordRotationTests(TestCase):
    def setUp(self):
        self.department = build_department()
        self.cluster = build_cluster(self.department)
        self.instance = build_instance(self.cluster)
        self.credential = build_credential(self.instance, password="Initial-Passw0rd!")

    def test_rotate_credential(self):
        log = services.rotate_credential(self.credential)
        self.credential.refresh_from_db()

        self.assertEqual(self.credential.password_version, 2)
        self.assertIsNotNone(self.credential.rotated_at)
        self.assertNotEqual(self.credential.get_password(), "Initial-Passw0rd!")
        self.assertEqual(log.get_old_password(), "Initial-Passw0rd!")
        self.assertEqual(log.get_new_password(), self.credential.get_password())
        self.assertTrue(log.success)
        self.assertEqual(CredentialRotationLog.objects.count(), 1)

    def test_rotation_due_flag(self):
        self.assertTrue(self.credential.is_rotation_due())  # 从未轮换过
        services.rotate_credential(self.credential)
        self.credential.refresh_from_db()
        self.assertFalse(self.credential.is_rotation_due())

        self.credential.rotated_at = timezone.now() - timedelta(hours=13)
        self.credential.save(update_fields=["rotated_at"])
        self.assertTrue(self.credential.is_rotation_due())

    def test_rotation_interval_zero_is_due_immediately(self):
        """周期 0 是合法值（立即到期），不能被当成未设置而回退到默认 12 小时。"""
        services.rotate_credential(self.credential)
        self.credential.refresh_from_db()
        self.assertFalse(self.credential.is_rotation_due())

        self.credential.rotate_interval_hours = 0
        self.credential.save(update_fields=["rotate_interval_hours"])

        # 刚刚轮换过，按默认 12 小时周期本不该到期；周期为 0 时应立即到期
        self.assertTrue(self.credential.is_rotation_due())
        result = services.rotate_passwords()
        self.assertEqual(result["success"], 1)
        self.assertEqual(result["skipped"], 0)

    def test_rotate_passwords_skips_credential_not_due(self):
        services.rotate_credential(self.credential)
        result = services.rotate_passwords()
        self.assertEqual(result["total"], 0)
        self.assertEqual(result["skipped"], 1)

        forced = services.rotate_passwords(force=True)
        self.assertEqual(forced["success"], 1)

    def test_rotate_passwords_task(self):
        result = rotate_instance_passwords.run()
        self.assertEqual(result["success"], 1)
        self.credential.refresh_from_db()
        self.assertEqual(self.credential.password_version, 2)

    def test_rotation_failure_is_recorded(self):
        original = services.rotate_credential

        def boom(credential, new_password=None):
            raise RuntimeError("模拟轮换失败")

        services.rotate_credential = boom
        try:
            result = services.rotate_passwords(force=True)
        finally:
            services.rotate_credential = original

        self.assertEqual(result["failed"], 1)
        log = CredentialRotationLog.objects.get()
        self.assertFalse(log.success)
        self.assertIn("模拟轮换失败", log.message)


# ---------------------------------------------------------------------------
# 每日统计
# ---------------------------------------------------------------------------
class InstanceStatsTests(TestCase):
    def setUp(self):
        self.department_a = build_department(name="A部", code="A")
        self.department_b = build_department(name="B部", code="B")
        self.cluster_a1 = build_cluster(self.department_a, name="a1", code="a1")
        self.cluster_a2 = build_cluster(self.department_a, name="a2", code="a2")
        self.cluster_b1 = build_cluster(self.department_b, name="b1", code="b1")

        build_instance(self.cluster_a1, name="x1", host="10.0.0.1", port=3306)
        build_instance(
            self.cluster_a1, name="x2", host="10.0.0.2", port=3306, status=InstanceStatus.OFFLINE
        )
        build_instance(self.cluster_b1, name="x3", host="10.0.0.3", port=3306)

    def test_collect_stats_by_department_and_cluster(self):
        result = services.collect_instance_stats()
        self.assertEqual(result["rows"], 3)
        self.assertEqual(result["instance_total"], 3)

        row = InstanceStatDaily.objects.get(cluster=self.cluster_a1)
        self.assertEqual(row.department_id, self.department_a.id)
        self.assertEqual(
            (row.instance_count, row.online_count, row.offline_count), (2, 1, 1)
        )
        # 没有实例的集群也会生成 0 行
        self.assertEqual(InstanceStatDaily.objects.get(cluster=self.cluster_a2).instance_count, 0)
        self.assertEqual(InstanceStatDaily.objects.get(cluster=self.cluster_b1).instance_count, 1)

    def test_collect_stats_is_idempotent(self):
        services.collect_instance_stats()
        services.collect_instance_stats()
        self.assertEqual(InstanceStatDaily.objects.count(), 3)

    def test_collect_stats_with_explicit_date(self):
        result = services.collect_instance_stats("2026-01-01")
        self.assertEqual(result["stat_date"], "2026-01-01")
        self.assertTrue(InstanceStatDaily.objects.filter(stat_date="2026-01-01").exists())

    def test_collect_stats_rejects_bad_date(self):
        with self.assertRaises(ValueError):
            services.collect_instance_stats("2026/01/01")

    def test_collect_daily_stats_task(self):
        result = collect_daily_instance_stats.run()
        self.assertEqual(result["rows"], 3)
        self.assertEqual(result["stat_date"], timezone.localdate().isoformat())


# ---------------------------------------------------------------------------
# 请求耗时中间件
# ---------------------------------------------------------------------------
class RequestTimingMiddlewareTests(TestCase):
    def setUp(self):
        reset_request_timing()

    def test_response_header_contains_duration(self):
        response = self.client.get("/api/health/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("X-Request-Duration-Ms", response)
        self.assertGreaterEqual(float(response["X-Request-Duration-Ms"]), 0.0)

    def test_snapshot_aggregates_by_route(self):
        self.client.get("/api/health/")
        self.client.get("/api/health/")
        counters = {item["route"]: item for item in request_timing_snapshot()}
        self.assertIn("GET /api/health/", counters)
        self.assertGreaterEqual(counters["GET /api/health/"]["count"], 2)


# ---------------------------------------------------------------------------
# REST 接口
# ---------------------------------------------------------------------------
class ApiTests(LocalTcpServerMixin, TestCase):
    def setUp(self):
        self.setUpLocalServer()
        reset_request_timing()
        self.client = APIClient()
        user = get_user_model().objects.create_user(username="tester", password="Passw0rd!234")
        self.client.force_authenticate(user=user)
        self.department = build_department()
        self.cluster = build_cluster(self.department)
        self.instance = build_instance(self.cluster, host="127.0.0.1", port=3306)

    # -- 部门 CRUD ---------------------------------------------------------
    def test_department_crud(self):
        created = self.client.post(
            "/api/departments/", {"name": "数据部", "code": "DATA"}, format="json"
        )
        self.assertEqual(created.status_code, 201, created.data)
        department_id = created.data["id"]

        detail = self.client.get(f"/api/departments/{department_id}/")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.data["code"], "DATA")

        updated = self.client.patch(
            f"/api/departments/{department_id}/", {"name": "数据平台部"}, format="json"
        )
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.data["name"], "数据平台部")

        deleted = self.client.delete(f"/api/departments/{department_id}/")
        self.assertEqual(deleted.status_code, 204)
        self.assertFalse(Department.objects.filter(pk=department_id).exists())

    def test_department_list_search_and_parent_name(self):
        child = Department.objects.create(name="交易平台部", code="TRADE", parent=self.department)
        response = self.client.get("/api/departments/", {"search": "交易"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["results"][0]["id"], child.id)
        self.assertEqual(response.data["results"][0]["parent_name"], self.department.name)

    def test_department_delete_protected_by_cluster(self):
        response = self.client.delete(f"/api/departments/{self.department.id}/")
        self.assertEqual(response.status_code, 400)
        self.assertIn("集群", str(response.data["detail"]))

    def test_department_cycle_is_rejected(self):
        child = Department.objects.create(name="子部门", code="CHILD", parent=self.department)
        response = self.client.patch(
            f"/api/departments/{self.department.id}/", {"parent": child.id}, format="json"
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("环", str(response.data))

    # -- 集群 / 实例 CRUD --------------------------------------------------
    def test_cluster_crud_with_instance_count(self):
        created = self.client.post(
            "/api/clusters/",
            {"name": "风控集群", "code": "risk", "department": self.department.id, "db_type": "redis"},
            format="json",
        )
        self.assertEqual(created.status_code, 201, created.data)
        self.assertEqual(created.data["department_name"], self.department.name)

        listing = self.client.get("/api/clusters/", {"department": self.department.id})
        self.assertEqual(listing.status_code, 200)
        counts = {item["code"]: item["instance_count"] for item in listing.data["results"]}
        self.assertEqual(counts["trade"], 1)
        self.assertEqual(counts["risk"], 0)

        deleted = self.client.delete(f"/api/clusters/{created.data['id']}/")
        self.assertEqual(deleted.status_code, 204)

    def test_instance_crud(self):
        created = self.client.post(
            "/api/instances/",
            {
                "name": "trade-02",
                "cluster": self.cluster.id,
                "host": "10.10.0.2",
                "port": 3307,
                "role": "slave",
            },
            format="json",
        )
        self.assertEqual(created.status_code, 201, created.data)
        self.assertEqual(created.data["endpoint"], "10.10.0.2:3307")
        self.assertEqual(created.data["department_name"], self.department.name)
        self.assertFalse(created.data["has_credential"])

        updated = self.client.patch(
            f"/api/instances/{created.data['id']}/", {"status": "maintenance"}, format="json"
        )
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.data["status"], "maintenance")

        detail = self.client.get(f"/api/instances/{created.data['id']}/")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.data["name"], "trade-02")

        deleted = self.client.delete(f"/api/instances/{created.data['id']}/")
        self.assertEqual(deleted.status_code, 204)

    def test_instance_filter_by_department_and_cluster(self):
        other_department = build_department(name="运营部", code="OPS")
        other_cluster = build_cluster(other_department, name="运营集群", code="ops")
        build_instance(other_cluster, name="ops-01", host="10.10.0.9", port=3306)

        by_department = self.client.get("/api/instances/", {"department": self.department.id})
        self.assertEqual(by_department.data["count"], 1)
        by_cluster = self.client.get("/api/instances/", {"cluster": other_cluster.id})
        self.assertEqual(by_cluster.data["count"], 1)
        bad_param = self.client.get("/api/instances/", {"department": "abc"})
        self.assertEqual(bad_param.status_code, 400)

    def test_instance_duplicate_endpoint_is_rejected(self):
        response = self.client.post(
            "/api/instances/",
            {"name": "trade-dup", "cluster": self.cluster.id, "host": "127.0.0.1", "port": 3306},
            format="json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("host", response.data)

    def test_instance_invalid_port_is_rejected(self):
        response = self.client.post(
            "/api/instances/",
            {"name": "trade-bad", "cluster": self.cluster.id, "host": "10.10.0.3", "port": 70000},
            format="json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("port", response.data)

    # -- TCP 端口探测接口 --------------------------------------------------
    def test_tcp_probe_api(self):
        port = self.start_server()
        instance = build_instance(
            self.cluster, name="probe-api", host="127.0.0.1", port=port, status=InstanceStatus.OFFLINE
        )
        response = self.client.post(f"/api/instances/{instance.id}/tcp-probe/", {}, format="json")
        self.assertEqual(response.status_code, 200, response.data)
        self.assertTrue(response.data["reachable"])
        self.assertEqual(response.data["host"], "127.0.0.1")
        self.assertEqual(response.data["port"], port)
        instance.refresh_from_db()
        self.assertTrue(instance.last_probe_ok)
        self.assertEqual(instance.status, InstanceStatus.ONLINE)

    def test_tcp_probe_api_unreachable(self):
        port = self.start_server()
        self.stop_servers()
        instance = build_instance(self.cluster, name="probe-down", port=port)
        response = self.client.post(f"/api/instances/{instance.id}/tcp-probe/", {}, format="json")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.data["reachable"])
        self.assertTrue(response.data["error"])

    def test_tcp_probe_api_instance_not_found(self):
        response = self.client.post("/api/instances/999999/tcp-probe/", {}, format="json")
        self.assertEqual(response.status_code, 404)

    def test_tcp_probe_all_api(self):
        port = self.start_server()
        build_instance(self.cluster, name="probe-all-up", port=port)
        response = self.client.post(
            "/api/instances/tcp-probe-all/?search=probe-all-up", {}, format="json"
        )
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["total"], 1)
        self.assertEqual(response.data["reachable"], 1)

    # -- 凭据接口 ----------------------------------------------------------
    def test_credential_api_hides_plaintext_password(self):
        created = self.client.post(
            "/api/credentials/",
            {"instance": self.instance.id, "username": "app", "password": "Sup3r-Secret!pwd"},
            format="json",
        )
        self.assertEqual(created.status_code, 201, created.data)
        self.assertNotIn("password", created.data)
        self.assertEqual(created.data["password_masked"], "********")
        credential_id = created.data["id"]

        detail = self.client.get(f"/api/credentials/{credential_id}/")
        self.assertEqual(detail.status_code, 200)
        self.assertNotIn("password", detail.data)
        self.assertFalse(detail.data["rotation_due"])

        stored = InstanceCredential.objects.get(pk=credential_id)
        self.assertNotIn("Sup3r-Secret!pwd", stored.password_ciphertext)

        reveal = self.client.get(f"/api/credentials/{credential_id}/reveal/")
        self.assertEqual(reveal.status_code, 200)
        self.assertEqual(reveal.data["password"], "Sup3r-Secret!pwd")

    def test_credential_password_generation_when_omitted(self):
        created = self.client.post(
            "/api/credentials/", {"instance": self.instance.id, "username": "auto"}, format="json"
        )
        self.assertEqual(created.status_code, 201, created.data)
        credential = InstanceCredential.objects.get(pk=created.data["id"])
        self.assertGreaterEqual(len(credential.get_password()), 12)

    def test_credential_update_password_rotates(self):
        credential = build_credential(self.instance, password="Old-Password!1")
        updated = self.client.patch(
            f"/api/credentials/{credential.id}/", {"password": "New-Password!2"}, format="json"
        )
        self.assertEqual(updated.status_code, 200, updated.data)
        credential.refresh_from_db()
        self.assertEqual(credential.password_version, 2)
        self.assertEqual(credential.get_password(), "New-Password!2")
        self.assertTrue(CredentialRotationLog.objects.filter(credential=credential).exists())

    def test_credential_rotate_action_and_logs(self):
        credential = build_credential(self.instance, password="Old-Password!1")
        response = self.client.post(f"/api/credentials/{credential.id}/rotate/", {}, format="json")
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["password_version"], 2)
        self.assertNotEqual(response.data["password"], "Old-Password!1")

        credential.refresh_from_db()
        self.assertEqual(credential.get_password(), response.data["password"])

        logs = self.client.get(f"/api/credentials/{credential.id}/rotation-logs/")
        self.assertEqual(logs.status_code, 200)
        self.assertEqual(logs.data[0]["success"], True)

        listing = self.client.get("/api/rotation-logs/", {"instance": self.instance.id})
        self.assertEqual(listing.data["count"], 1)

    def test_instance_rotate_password_action(self):
        build_credential(self.instance, password="Old-Password!1")
        response = self.client.post(
            f"/api/instances/{self.instance.id}/rotate-password/", {}, format="json"
        )
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["username"], "app")
        self.assertIn("password", response.data)

    def test_instance_rotate_password_without_credential(self):
        response = self.client.post(
            f"/api/instances/{self.instance.id}/rotate-password/", {}, format="json"
        )
        self.assertEqual(response.status_code, 404)

    # -- 统计接口 ----------------------------------------------------------
    def test_daily_stats_collect_and_list(self):
        collected = self.client.post("/api/daily-stats/collect/", {}, format="json")
        self.assertEqual(collected.status_code, 201, collected.data)
        self.assertEqual(collected.data["rows"], 1)

        listing = self.client.get("/api/daily-stats/")
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(listing.data["count"], 1)
        self.assertEqual(listing.data["results"][0]["instance_count"], 1)

        filtered = self.client.get("/api/daily-stats/", {"department": self.department.id})
        self.assertEqual(filtered.data["count"], 1)

        bad_date = self.client.get("/api/daily-stats/", {"stat_date": "2026/01/01"})
        self.assertEqual(bad_date.status_code, 400)

    def test_request_timing_endpoint(self):
        self.client.get("/api/instances/")
        response = self.client.get("/api/request-timing/")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["counters"])

    def test_health_endpoint(self):
        response = self.client.get("/api/health/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["status"], "ok")
