# NetAgent

> 终端版网络流量分析与安全检测 Agent —— 当前处于早期开发阶段，尚未完成。

NetAgent 是一个权限感知的网络监控与分析 TUI 工具。它通过 OpenTUI + TypeScript/Bun 构建前端界面，Rust 构建后端核心，二者通过 stdio JSON-RPC 通信。

**注意：项目仍在开发中，许多功能尚未实现或仅具备 mock 能力，请勿用于生产环境。**

## 架构

```
OpenTUI / TypeScript / Bun (UI)
  └── Dashboard / Flows / Alerts / Agent Chat / Approval Modal
        │
        │ stdio JSON-RPC
        │
Rust Core
  ├── JSON-RPC Server
  ├── Agent Runtime
  ├── Permission Manager (权限状态机)
  ├── Tool Registry (工具执行)
  ├── Capture Manager (tcpdump 抓包)
  ├── Parser (tshark 解析 pcap)
  ├── Analyzers (DNS 异常检测等)
  ├── SQLite Storage
  └── Artifact Store
```

## 当前能力（Phase 7）

| 模块 | 状态 |
|------|------|
| JSON-RPC 通信 | 18 个方法可用 |
| 权限状态机 | once / always / reject / reject_with_feedback |
| tcpdump 抓包 | 已接入，需系统权限 |
| tshark pcap 解析 | 已接入，提取 flow 和 DNS |
| SQLite 持久化 | flows / dns_events / findings 三表 |
| DNS NXDOMAIN 检测 | 已实现 |
| OpenTUI 仪表盘 | 基础单屏界面 |

## 快速开始

### 环境要求

- Rust (nightly)
- Bun
- tshark (可选，pcap 解析需要)

### 启动 Rust Core

```bash
cargo run -p netagent-core
```

Core 启动后监听 stdin，接受 JSON-RPC 请求：

```bash
# 连通性检查
printf '{"jsonrpc":"2.0","id":1,"method":"system.ping","params":{}}\n' | cargo run -q -p netagent-core

# 查看能力列表
printf '{"jsonrpc":"2.0","id":1,"method":"core.capabilities","params":{}}\n' | cargo run -q -p netagent-core

# 解析 pcap 文件
printf '{"jsonrpc":"2.0","id":1,"method":"pcap.open","params":{"path":"/path/to/file.pcap"}}\n' | cargo run -q -p netagent-core

# 查看已存储的 flow
printf '{"jsonrpc":"2.0","id":1,"method":"flow.list","params":{}}\n' | cargo run -q -p netagent-core

# 运行 DNS 异常检测
printf '{"jsonrpc":"2.0","id":1,"method":"dns.detect_anomalies","params":{"threshold_ratio":0.3}}\n' | cargo run -q -p netagent-core
```

### 启动 UI

```bash
cd ui/opentui-app
bun install
bun run src/main.tsx
```

## 项目结构

```
ngentv2/
  crates/
    netagent-core/     # Rust 核心进程
    netagent-models/   # 共享数据模型
  ui/opentui-app/      # OpenTUI 前端
  config/              # 示例配置文件
  rules/builtin/       # 检测规则
  schemas/             # JSON Schema
  examples/            # 示例 pcap 和配置
  tests/               # 测试固件
```

## 开发

```bash
cargo check           # 类型检查
cargo test            # 运行测试
cargo run -p netagent-core  # 启动核心
```

## 已知限制

- 实时抓包需要系统权限（macOS 下需配置 `/dev/bpf` 访问）
- 端到端 pcap 解析未在本机完整验证
- 报告生成、IOC 导出尚未实现（Phase 8）
- UI 为基础单屏版本，交互有限
- Agent 问答为 mock 实现，未接入真实 LLM

## 路线图

| Phase | 内容 | 状态 |
|-------|------|------|
| 0 | 项目骨架 | ✅ |
| 1 | JSON-RPC 协议与 Harness | ✅ |
| 2 | Agent Runtime | ✅ |
| 3 | 权限状态机 | ✅ |
| 4 | Tool Runtime 与 Artifact Store | ✅ |
| 5 | UI 基本视图 | ✅ |
| 6 | 真实抓包 (tcpdump) | ✅ |
| 7 | pcap 解析与首个检测规则 | ✅ |
| 8 | 报告生成 | 待开发 |

## 许可证

MIT
