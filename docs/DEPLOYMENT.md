# kcatta 部署与运维入口

本文只记录部署相关事实：本地 compose 栈、环境变量、安全默认值、agent 投放二进制与验证命令。组件内部用法仍以各组件 README 为准。

## 1. 本地 compose 栈

```bash
cd kcatta
make compose-config       # 校验 docker-compose.yml 语法与插值
make compose-up           # 等价于 docker compose up --build
# 浏览器访问 http://localhost:10063
make compose-down
```

compose 启动三个服务：

| 服务 | 暴露面 | 作用 |
| --- | --- | --- |
| `token-init` | 不暴露端口 | 首次启动时生成强随机 `ANALYZER_API_TOKEN`，写入私有卷 `kcatta-secrets` |
| `analyzer` | 仅 compose 网络 `10068` | FastAPI 后端，SQLite 存储，读取同一 token |
| `admin` | 主机 `10063` | Next.js 控制台；服务端通过 `http://analyzer:10068` 调 analyzer |

默认无需 `.env`：未显式设置 `ANALYZER_API_TOKEN` 时，`token-init` 会生成并复用一个部署内 token。需要让外部 agent 或其它系统共享同一 token 时，再在 shell 或 `.env` 中显式设置。

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
ANALYZER_API_TOKEN=<上一步输出> docker compose up --build
```

`docker compose down -v` 会删除 `kcatta-secrets` 卷；下次启动会生成新 token。

## 2. 生产暴露面

- analyzer 默认不发布到宿主机；生产中若必须暴露，应经反向代理收敛到 TLS + 鉴权网络边界。
- admin 是唯一默认发布端口；生产中也应放在 TLS / SSO / VPN 后面，不要直接暴露到不可信网络。
- analyzer 未设置 `ANALYZER_API_TOKEN` 时会开放除 `/health` 外的所有 API；这只适合裸机本地开发。compose 不使用空鉴权：它会自动生成 token。
- 可选设置 `ANALYZER_INGEST_TOKEN`，只给 endpoint guard 分发 ingest 级 token，避免把 master token 放到被监控主机上。

## 3. agent 投放二进制

SSH/Linux 远程扫描由 analyzer 投放静态 musl 二进制。每个架构需要三件产物：

| 文件 | 用途 |
| --- | --- |
| `agent-collect-host` | host 一次性静态采集 |
| `agent-collect-trace` | trace 一次性捕获 |
| `agentd` | guard 常驻守护；只有 `agentd` 负责上报 |

本地构建：

```bash
make build-agent-deploy         # x86_64-unknown-linux-musl；需 musl-tools
make build-agent-deploy-arm64   # aarch64-unknown-linux-musl；需 cross
```

analyzer 按目标 `uname -m` 自动从 `ANALYZER_AGENT_TARGET_DIR/<triple>/release/<bin>` 选择二进制。默认 `ANALYZER_AGENT_TARGET_DIR=../agent/target`；容器镜像内默认是 `/opt/kcatta/agent-bins`。

当前 analyzer 容器内置 x86_64 musl 的 `agent-collect-host`、`agent-collect-trace` 与 `agentd`，因此 x86_64 Linux 目标可直接从 compose 栈触发 host/trace/guard。扫描 aarch64 目标时，需要另外构建 arm64 产物并挂载到 `ANALYZER_AGENT_TARGET_DIR`。

## 4. 本机扫描（transport=local）

`transport=local` 不走 SSH，直接在 analyzer 主机执行本机架构的 `agent-collect-host`，仅支持 host 能力。

容器内默认扫描 analyzer 容器自身。要扫描宿主机，将宿主根目录只读挂载，并设置扫描根：

```yaml
services:
  analyzer:
    volumes:
      - /:/host:ro
    environment:
      ANALYZER_LOCAL_SCAN_ROOT: /host
```

## 5. 部署前验证

```bash
make compose-config
make schema-check
make contracts-check
```

针对具体改动再跑组件级验证：

```bash
make test-analyzer
make test-admin
make test-agent
```

CI 分别覆盖 Rust agent、Windows 构建、musl 投放构建、Python analyzer、Next admin、schema/contract 漂移、DCO、secret scan、dependency audit 与 e2e smoke。分支保护所需 check 名称见 `.github/BRANCH_PROTECTION.md`，脚本入口见 `scripts/setup-branch-protection.sh`。