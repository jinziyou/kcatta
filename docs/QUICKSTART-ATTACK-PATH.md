# 从 0 到第一次 Attack Path

最短闭环：拉起蓝队栈 → 确认检测语料就绪 → 本机 host 扫描 → 灌入能力图 → 查看攻击路径。

## 前置

- Docker + Compose（或本机 Python/Node/Rust 工具链）
- 授权范围内的目标（本示例使用 `transport=local`，只扫 Form 所在主机）

## 1. 启动栈

```bash
cd kcatta
make compose-up
# Admin  → http://127.0.0.1:10063
# Form   → http://127.0.0.1:10067
# Agent  → https://127.0.0.1:10443  (mTLS)
```

令牌由 `token-init` 写入 named volume。查看：

```bash
docker compose exec form printenv FORM_API_TOKEN ANALYZER_INTERNAL_TOKEN
```

## 2. 确认 OSV 就绪

Compose 会在持久卷为空时自动同步 OSV。空库或不完整语料时 Analyzer `/ready`
返回降级状态（HTTP 仍为 200），对应 `DetectionResult` 会明确标为
`disabled/partial`，不会把未检测伪装成零漏洞。

```bash
# 可选的手工刷新（或用于非 compose 部署）
make osv-sync
# 等价：cd analyzer && .venv/bin/analyzer-osv-sync
```

确认：

```bash
curl -sS http://127.0.0.1:10068/ready
# {"status":"ready","osv":"ready","osv_record_count":...}
```

（Analyzer 默认仅 compose 内网可达；本机直跑时才有 10068 宿主机映射。）

## 3. Admin 注册本机目标并扫描

1. 打开 Admin → **目标** → 传输选 **本机** → 注册。
2. **扫描** → 能力选 **host** → 触发。
3. 任务进入 `succeeded` 后到 **资产报告 / 漏洞** 查看结果。

或用 API（将 `$FORM_TOKEN` 换成控制令牌）：

```bash
curl -sS -H "Authorization: Bearer $FORM_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"local","address":"localhost","transport":"local","credential_mode":"none"}' \
  http://127.0.0.1:10067/targets

# 记下 target_id 后：
curl -sS -H "Authorization: Bearer $FORM_TOKEN" -H 'Content-Type: application/json' \
  -H "Idempotency-Key: demo-host-1" \
  -d '{"target_id":"<TARGET_ID>","capability":"host"}' \
  http://127.0.0.1:10067/scans
```

## 4. 灌入能力图（红队 / 紫队）

kcatta 不执行攻击；它只消费 `CapabilityGraph`：

```bash
# 经 Form 公共入口（推荐）
curl -sS -H "Authorization: Bearer $FORM_TOKEN" -H 'Content-Type: application/json' \
  -d @capability-graph.json \
  http://127.0.0.1:10067/ingest/capability-graph
```

紫队 `loop sync-capgraph` 会把 att7ck 能力图翻译后 POST 到同一路径。

## 5. 查看攻击路径

- Admin → **攻击路径** → 打开详情（React Flow 图）
- 或 API：`GET http://127.0.0.1:10067/attack-paths`（Form facade）

路径推导依赖：能力图 + 已 ingest 的主机态势（包/端口/凭据等）。若列表为空，先确认 host 扫描成功且能力图已 ingest。

## 6. 可选：定时扫描与 Admin 口令

```bash
# 每 60 分钟对本机目标做 host 扫描
curl -sS -H "Authorization: Bearer $FORM_TOKEN" -H 'Content-Type: application/json' \
  -d '{"target_id":"<TARGET_ID>","capability":"host","interval_minutes":60}' \
  http://127.0.0.1:10067/schedules
```

Admin 可选 HTTP Basic（`ADMIN_BASIC_AUTH_USER` + `ADMIN_BASIC_AUTH_PASSWORD`）。

## 7. 探针与指标

| 端点 | 含义 |
| --- | --- |
| Analyzer `GET /health` | 进程存活 |
| Analyzer `GET /ready` | 200 可服务；`osv=empty` 时 `status=degraded` |
| Analyzer `GET /metrics`（需 metrics-only token） | Prometheus 文本 |
| Form `GET /ready`（需 control token） | analyzer + worker + scheduler + osv 汇总 |
| Form `GET /metrics`（需 metrics-only token） | Prometheus 文本 |

## 边界提醒

- 仅扫你有权扫的资产。
- Admin 默认回环绑定；上线前加 VPN/Basic，勿裸奔 `0.0.0.0`。
- 生产 Agent 使用 per-Agent mTLS；迁完后切 `FORM_AGENT_AUTH_MODE=mtls`。
