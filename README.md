# 数据库实例管理系统（Database Instance Manager）

基于 **Django + DRF + Celery** 的企业内部数据库实例管理系统，用于统一管理数据库实例、集群、部门，
并对实例的账号密码进行加密托管与自动轮换。

## 需求实现对照

| # | 需求 | 实现位置 |
|---|------|----------|
| 1 | 设计实例 / 集群 / 部门等模型 | [models.py](instances/models.py)：`Department` / `Cluster` / `Instance` / `InstanceCredential` / `CredentialRotationLog` / `InstanceStatDaily` |
| 2 | 提供模型增删改查接口 + TCP 端口可达性探测 API | [views.py](instances/views.py)（4 个 ModelViewSet + 自定义 action）、[urls.py](instances/urls.py) |
| 3 | 维护实例账号密码，每 12 小时随机轮换并加密记录 | [services.py](instances/services.py) 的 `rotate_credential` / `rotate_passwords`、[crypto.py](instances/crypto.py) Fernet 加密、[tasks.py](instances/tasks.py) 定时任务 |
| 4 | 每天 00:00 按部门 + 集群统计实例数量并写库 | `services.collect_instance_stats` + `tasks.collect_daily_instance_stats`（Celery Beat `crontab(minute=0, hour=0)`）|
| 5 | 中间件统计每个请求的请求耗时 | [middleware.py](instances/middleware.py) `RequestTimingMiddleware` |

## 技术栈

- Python 3.10+ / Django 4.2 / Django REST framework 3.15
- Celery 5.4 + Redis（消息队列与 Beat 调度）
- cryptography（Fernet 对称加密存储实例密码）
- 默认 SQLite，可通过环境变量切换 PostgreSQL

## 目录结构

```
database-instance-manager/
├── config/
│   ├── settings.py          # 配置（数据库、DRF、Celery Beat、日志、密钥）
│   ├── celery.py            # Celery 应用
│   └── urls.py
├── instances/
│   ├── models.py            # 部门 / 集群 / 实例 / 凭据 / 轮换日志 / 每日统计
│   ├── serializers.py       # DRF 序列化器
│   ├── views.py             # CRUD + TCP 探测 / 密码轮换 / 统计接口
│   ├── services.py          # 随机密码、TCP 探测、轮换、统计等业务逻辑
│   ├── tasks.py             # Celery 定时任务
│   ├── middleware.py        # 请求耗时统计中间件
│   ├── crypto.py            # 凭据加解密
│   ├── admin.py             # 后台管理
│   ├── tests.py             # 单元测试 + 接口测试
│   └── migrations/0001_initial.py
├── manage.py
├── requirements.txt
└── .env.example
```

## 数据模型

| 模型 | 说明 | 关键字段 |
|------|------|----------|
| `Department` | 部门，支持上下级树（自关联，禁止成环） | name、code、parent |
| `Cluster` | 数据库集群，隶属部门（删除部门受 PROTECT 保护） | name、code、department、db_type |
| `Instance` | 数据库实例 | name、cluster、host、port、role、status、last_probe_at、last_probe_ok；(cluster, host, port) 唯一 |
| `InstanceCredential` | 实例账号密码（密码仅存密文） | instance(1:1)、username、password_ciphertext、password_version、rotated_at、rotate_interval_hours、auto_rotate_enabled |
| `CredentialRotationLog` | 密码轮换审计，新旧密码均以密文留存 | credential、instance、old/new_password_ciphertext、success、message |
| `InstanceStatDaily` | 每日统计快照，(stat_date, department, cluster) 唯一；**cluster 为空的行是部门级汇总行**（该部门下所有集群合计） | instance_count、online_count、offline_count |

## 快速开始

```bash
# 1. 安装依赖（建议使用虚拟环境）
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate
pip install -r requirements.txt

# 2. 初始化数据库
python manage.py migrate
python manage.py createsuperuser          # 可选，用于 /admin 与需要登录的生产接口

# 3. 启动 Web 服务
python manage.py runserver 0.0.0.0:8000

# 4. 另开两个终端启动异步任务（需要 Redis）
celery -A config worker -l info
celery -A config beat -l info            # 定时调度：12 小时轮换、每日统计
```

Redis 也可以不启动：此时 CRUD/探测/统计接口仍可用，只是无法通过 `.delay()` 异步执行任务。
在没有 Redis 的环境下可直接调用任务函数（例如 `python manage.py shell` 中执行
`from instances.tasks import collect_daily_instance_stats; collect_daily_instance_stats()`），
或使用统计接口 `POST /api/daily-stats/collect/`。

## API 一览

统一前缀 `/api/`。开发环境（`DEBUG=1`）默认允许匿名访问，生产环境通过 `API_ALLOW_ANONYMOUS=0` 开启鉴权
（Basic / Session 认证）。

| 方法 | 路径 | 说明 |
|------|------|------|
| GET / POST | `/api/departments/` | 部门列表（分页）/ 新建 |
| GET / PUT / PATCH / DELETE | `/api/departments/{id}/` | 部门详情 / 更新 / 删除（部门下有集群时返回 400） |
| GET / POST | `/api/clusters/` | 集群列表 / 新建，支持 `?department=&db_type=&search=&ordering=` |
| GET / PUT / PATCH / DELETE | `/api/clusters/{id}/` | 集群详情 / 更新 / 删除 |
| GET / POST | `/api/instances/` | 实例列表 / 新建，支持 `?cluster=&department=&db_type=&status=&reachable=&search=` |
| GET / PUT / PATCH / DELETE | `/api/instances/{id}/` | 实例详情 / 更新 / 删除 |
| **POST** | `/api/instances/{id}/tcp-probe/` | **探测该实例 TCP 端口是否可达**，并回写 `last_probe_at` / `last_probe_ok` / `status` |
| POST | `/api/instances/tcp-probe-all/` | 批量探测（支持列表接口的过滤参数） |
| POST | `/api/instances/{id}/rotate-password/` | 立即随机轮换该实例密码（返回一次性明文） |
| GET / POST | `/api/credentials/` | 凭据列表 / 新建（`password` 只写，响应中不含明文） |
| GET / PUT / PATCH / DELETE | `/api/credentials/{id}/` | 凭据详情 / 更新（提交 `password` 即触发轮换）/ 删除 |
| GET | `/api/credentials/{id}/reveal/` | 显式读取明文密码 |
| POST | `/api/credentials/{id}/rotate/` | 立即随机轮换密码 |
| GET | `/api/credentials/{id}/rotation-logs/` | 该凭据的轮换历史 |
| GET | `/api/rotation-logs/` | 轮换审计日志（只读），支持 `?instance=&credential=&success=` |
| GET | `/api/daily-stats/` | 每日统计查询，支持 `?stat_date=&start_date=&end_date=&department=&cluster=` |
| POST | `/api/daily-stats/collect/` | 手动触发统计落库（等价于每日 00:00 任务） |
| GET | `/api/request-timing/` | 请求耗时统计（按路由聚合：次数 / 平均 / 最大 / 慢请求数） |
| GET | `/api/health/` | 健康检查 |

### 调用示例

```bash
# 新建部门 / 集群 / 实例
curl -X POST http://127.0.0.1:8000/api/departments/ -H "Content-Type: application/json" \
     -d '{"name":"平台研发部","code":"PLATFORM"}'
curl -X POST http://127.0.0.1:8000/api/clusters/ -H "Content-Type: application/json" \
     -d '{"name":"交易集群","code":"trade","department":1,"db_type":"mysql"}'
curl -X POST http://127.0.0.1:8000/api/instances/ -H "Content-Type: application/json" \
     -d '{"name":"trade-01","cluster":1,"host":"127.0.0.1","port":3306,"role":"master"}'

# 探测实例 TCP 端口可达性
curl -X POST http://127.0.0.1:8000/api/instances/1/tcp-probe/

# 为实例配置账号密码（password 可省略，省略时自动生成随机密码）
curl -X POST http://127.0.0.1:8000/api/credentials/ -H "Content-Type: application/json" \
     -d '{"instance":1,"username":"app","password":"Initial-Passw0rd!"}'

# 读取明文密码 / 立即轮换密码
curl http://127.0.0.1:8000/api/credentials/1/reveal/
curl -X POST http://127.0.0.1:8000/api/credentials/1/rotate/

# 手动触发统计并查询
curl -X POST http://127.0.0.1:8000/api/daily-stats/collect/
curl "http://127.0.0.1:8000/api/daily-stats/?stat_date=2026-10-16"
```

## 定时任务（Celery Beat）

| 任务 | 调度 | 说明 |
|------|------|------|
| `instances.tasks.rotate_instance_passwords` | `crontab(minute=0, hour="*/12")`，即每 12 小时（00:00 / 12:00） | 为已到期的实例随机生成新密码，加密入库并写审计日志；可用 `force=True` 强制轮换 |
| `instances.tasks.collect_daily_instance_stats` | `crontab(minute=0, hour=0)`，即每天 00:00 | 按部门 + 集群维度统计实例数量（含 0 实例的集群），`update_or_create` 幂等落库 |
| `instances.tasks.probe_all_instances` | `crontab(minute="*/5")` | 每 5 分钟刷新全部实例的端口可达状态 |

## 密码与安全设计

- 密码使用 **Fernet 对称加密**后写入 `password_ciphertext`，数据库与接口响应中均不出现明文；
  轮换时同时把旧、新密码的密文写入 `CredentialRotationLog`，便于审计。
- 加密密钥来自 `CREDENTIAL_ENCRYPTION_KEY`；未配置时由 `SECRET_KEY` 派生（仅建议本地开发）。
  生成新密钥：
  `python -c "from instances.crypto import generate_encryption_key; print(generate_encryption_key())"`
- 密钥变更会导致历史密文无法解密，`reveal` 接口会返回 409 而不是抛出 500。
- API 默认不返回明文密码，只有 `reveal` / `rotate` 动作会返回一次明文，且提示及时保存。

## 请求耗时统计

`RequestTimingMiddleware` 位于中间件最外层，可统计包含全部中间件在内的完整请求耗时：

- 每个响应都会带上 `X-Request-Duration-Ms` 响应头；
- 按 `METHOD 路由模板` 聚合次数 / 总耗时 / 平均耗时 / 最大耗时 / 慢请求数，通过 `GET /api/request-timing/` 查看；
- 超过 `REQUEST_TIMING_SLOW_THRESHOLD_MS`（默认 500ms）的请求会输出 WARNING 日志，正常请求输出 INFO 日志。

## 运行测试

```bash
python manage.py test
```

覆盖内容：加解密往返、随机密码复杂度、TCP 探测（真实监听本地端口）、密码轮换与周期判断、
轮换失败落审计、部门 / 集群 / 实例 CRUD、TCP 探测接口、凭据接口不泄露明文、
每日统计幂等与维度正确性、中间件耗时响应头与聚合统计。

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `DJANGO_SECRET_KEY` | dev 默认值 | 生产环境必须替换 |
| `DJANGO_DEBUG` | `1` | 生产环境设为 `0` |
| `DJANGO_ALLOWED_HOSTS` | `*` | 逗号分隔 |
| `API_ALLOW_ANONYMOUS` | 与 DEBUG 一致 | 是否允许匿名访问 API |
| `CREDENTIAL_ENCRYPTION_KEY` | 空 | Fernet key，生产环境必须显式配置 |
| `CREDENTIAL_ROTATE_INTERVAL_HOURS` | `12` | 密码轮换周期，需与 Beat 调度保持一致 |
| `CREDENTIAL_PASSWORD_LENGTH` | `24` | 随机密码长度（最小 12） |
| `TCP_PROBE_TIMEOUT_SECONDS` | `3` | 端口探测超时 |
| `REQUEST_TIMING_SLOW_THRESHOLD_MS` | `500` | 慢请求告警阈值 |
| `DB_ENGINE` / `DB_NAME` / `DB_USER` / `DB_PASSWORD` / `DB_HOST` / `DB_PORT` | sqlite | `DB_ENGINE=postgres` 时启用 PostgreSQL |
| `CELERY_BROKER_URL` / `CELERY_RESULT_BACKEND` | redis 127.0.0.1 | 消息队列与结果后端 |

## 提交到 GitHub

```bash
cd database-instance-manager
git init
git add .
git commit -m "feat: 数据库实例管理系统（实例/集群/部门管理、TCP 探测、密码轮换、每日统计、请求耗时中间件）"
git branch -M main
git remote add origin https://github.com/<你的用户名>/<仓库名>.git
git push -u origin main
```

若已安装并登录 GitHub CLI，可一条命令创建远端仓库并推送：

```bash
gh repo create database-instance-manager --public --source=. --push
```

提交前请确认 `.env`、`db.sqlite3` 等本地文件未被纳入版本控制（已在 `.gitignore` 中忽略）。
