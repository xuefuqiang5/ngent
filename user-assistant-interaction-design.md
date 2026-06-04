# NetAgent User-Assistant 交互设计

本文承接 `netagent_build_spec.md` 第 20 节、第 21 节，以及 `project-debug-notes.md` 中对 OpenCode agent 调试得到的 Session / Message / Part / RunLoop 经验，目标是把 NetAgent 的用户与 assistant 交互抽象固定下来。

这份文档不是替代现有规格，而是补齐“用户输入如何进入 agent runtime、assistant 如何推进多步任务、UI 如何稳定展示状态、实现 agent 如何避免跑偏”的设计层。后续实现时应把本文作为 Phase 8 之后继续增强 Agent Runtime 与产品体验的约束文档。

## 1. 设计目标

NetAgent 的 assistant 不是单轮问答窗口，也不是网络工具菜单包装。它应该是一个可持续运行、可恢复、可观察、权限可控、证据可追溯的网络分析任务系统。

核心目标：

- 用户始终知道 assistant 当前处于什么状态：思考、执行工具、等待权限、分析、报告、失败、取消或完成。
- assistant 的每一步都能落到结构化状态，而不是只追加一段字符串。
- UI 只显示 Core 暴露的状态和事件，不直接执行系统命令、不自行判断风险。
- 工具执行必须走 Permission Manager、Tool Runtime、RunState、Artifact Store。
- 原始 pcap、tshark JSON、stdout/stderr、大日志只进入 artifact 或结构化存储，LLM 和 UI 只接收有界摘要与证据引用。
- 后续实现 agent 必须能从阶段、状态、事件和验收清单判断自己是否跑偏。

## 2. 当前阶段定位

根据 `HANDOFF.md`，当前仓库状态是 `Phase 8: Reports`：

- Phase 0-5 已完成基础 workspace、协议、mock agent runtime、权限状态机、tool runtime/artifact skeleton、最小 UI。
- Phase 6 已有真实 `tcpdump` 短时抓包路径，但受本机权限影响可能无法实际抓包。
- Phase 7 已有 `pcap.open`、`tshark.extract_flows`、`tshark.extract_dns`、SQLite persistence 和 NXDOMAIN finding。
- Phase 8 已有 `report.generate`、`ioc.export`、报告/IOC artifact 和 `report.generated`。

本文不要求重新实现 Phase 2-4，也不要求跳到 Zeek、Suricata、外部情报或响应处置。它定义的是 Phase 8 之后应补强的交互层和 runtime 成熟度闭环。

建议把后续工作命名为：

```text
Phase 9: User-Assistant Interaction Maturity
```

Phase 9 的最小闭环不是做大型 UI，而是让已有 Agent Runtime 从“mock turn + 事件展示”进化为“真实 session/message/part 驱动的可恢复交互”。

## 3. 核心抽象

NetAgent 的 user-assistant 交互应使用以下稳定层级：

```text
Workspace
  -> Case
     -> Session
        -> Message
           -> MessagePart
        -> Step
           -> ToolCall
              -> ToolResult
              -> ArtifactRef
        -> PermissionRequest
        -> RunState
```

### 3.1 Workspace

Workspace 表示当前项目工作区。它承载配置、权限规则、artifact 根目录、数据库路径和 Core 能力。

职责：

- 提供 `core.capabilities`。
- 声明协议版本和事件能力。
- 管理全局 permission ruleset 与项目级 always allow rule。
- 不直接保存单轮对话细节。

### 3.2 Case

Case 表示一次网络分析案件或调查上下文。一个 Case 可以包含多个 Session、多个 pcap、多个 finding 和报告。

最小字段：

```text
Case
  id
  title
  status: open | archived
  created_at
  updated_at
  primary_session_id?
  artifact_refs[]
  finding_ids[]
```

Phase 9 可以先不实现完整 Case API，但设计上应预留 `case_id`，避免未来把 session 当成唯一业务边界。

### 3.3 Session

Session 是一整条用户与 assistant 的任务线程，不是一条用户消息。

最小字段：

```text
Session
  id
  case_id?
  title
  mode: observe | capture | investigate | report | respond
  run_state
  max_steps
  created_at
  updated_at
  completed_at?
  error?
  compacted_summary_ref?
```

关键规则：

- 第一次用户输入前必须先创建 Session。
- 后续 prompt 都追加到同一个 `session_id`。
- 同一个 Session 同一时间只能有一个主 AgentLoop。
- 多个 Session 可以并行，但共享 capture/job/artifact 时必须通过 Core 的 RunState 和 BackgroundJob 管理。

### 3.4 Message

Message 是一次 user 输入或 assistant 输出容器。

最小字段：

```text
Message
  id
  session_id
  role: user | assistant | system
  agent_mode
  model?
  parent_message_id?
  finish_reason?
  error?
  token_usage?
  created_at
  completed_at?
```

规则：

- 每次用户 prompt 创建一个 `role=user` message。
- 每次 assistant 模型输出创建一个 `role=assistant` message。
- 工具结果优先作为 assistant message 的 tool/result part 保存；向模型适配时再转换为 provider 所需的 tool result 消息格式。

### 3.5 MessagePart

MessagePart 是 UI、模型上下文和持久化的最小渲染单元。

建议类型：

```text
text
reasoning
tool_call
tool_result
permission
artifact_ref
finding_ref
report_ref
context_summary
compaction
subtask
error
```

最小字段：

```text
MessagePart
  id
  session_id
  message_id
  kind
  status: pending | streaming | completed | error | aborted
  content_summary
  payload
  artifact_refs[]
  evidence_refs[]
  created_at
  updated_at
```

规则：

- UI 按 part 类型渲染，不解析 assistant 文本来猜测工具状态。
- 大输出不进入 `content_summary`，必须放进 artifact 并用 `artifact_refs` 引用。
- `reasoning` 默认可折叠，后续可以按模型/配置决定是否显示。

### 3.6 Step

Step 表示 AgentLoop 的一次推进单元。一个用户 prompt 可能产生多个 Step。

```text
Step
  id
  session_id
  assistant_message_id
  index
  status: pending | running | waiting_permission | completed | failed | aborted
  reason: model | tool_result_continuation | compaction | subtask
  started_at
  ended_at?
```

规则：

- 每个 Step 最多对应一次模型流式输出。
- 如果模型请求工具，Step 可以进入 `completed`，然后 AgentLoop 继续创建下一个 Step，把 tool result 回灌给模型。
- 如果等待权限，Step 进入 `waiting_permission`，Session 的 RunState 同步为 `waiting_permission`。

### 3.7 ToolCall

ToolCall 是工具调用生命周期的核心状态对象。

```text
ToolCall
  id
  session_id
  step_id
  message_id
  part_id
  tool_id
  input
  input_preview
  permission_request_id?
  status: pending | waiting_permission | running | completed | error | aborted
  progress?
  result_summary?
  artifact_refs[]
  raw_output_artifact?
  created_at
  updated_at
```

状态规则：

```text
pending
  -> waiting_permission?
  -> running
  -> completed | error | aborted
```

禁止：

- ToolCall 不带 `session_id` / `step_id` / `call_id` 就执行。
- ToolResult 返回未截断大 stdout 给 LLM。
- UI 或 Harness 绕过 Tool Runtime 调用系统命令。

### 3.8 PermissionRequest

PermissionRequest 是状态机，不是 UI modal boolean。

```text
PermissionRequest
  id
  session_id
  case_id?
  permission
  patterns[]
  always[]
  risk: low | medium | high
  status: pending | approved_once | approved_always | rejected | expired | canceled
  metadata:
    tool
    command_preview
    reason
    expected_artifact?
    timeout?
  tool:
    message_id
    call_id
  created_at
  resolved_at?
```

用户回复：

```text
once
always
reject
reject_with_feedback
```

`reject_with_feedback` 必须回到 AgentLoop，让 assistant 改方案，而不是只显示失败。

## 4. 交互生命周期

### 4.1 第一次输入

```text
User 输入
  -> UI 调用 session.create 或 agent.ask 无 session_id
  -> Core 创建 Session
  -> Core 创建 user Message
  -> Core 拆分 user MessagePart
  -> AgentLoop.ensure_running(session_id)
  -> 创建 assistant Message
  -> 创建 Step
  -> ContextBuilder 构造模型上下文
  -> Processor 处理模型流
  -> Tool Runtime / Permission / Artifact Store 按需介入
  -> assistant Message 完成
  -> Session 回到 idle 或进入明确状态
```

Phase 9 可以选择让 `agent.ask` 自动创建默认 Session，但 Core 返回值必须包含 `session_id`，UI 后续输入必须带回该 id。

### 4.2 后续输入

```text
User 在已有 Session 输入
  -> UI 调用 agent.ask({ session_id, input })
  -> Core 检查 Session 是否 running
  -> 若 idle/error/completed 可继续，则追加 user Message
  -> 若 busy/waiting_permission/canceling，则返回结构化冲突错误或排队策略
  -> AgentLoop 推进
```

默认策略：

- `idle`：立即运行。
- `busy/analyzing/reporting/capturing`：拒绝同 session 并提示当前正在运行。
- `waiting_permission`：不接受新 prompt 覆盖 pending request；用户必须先 approve/reject/cancel。
- `error`：允许用户继续输入，assistant 解释错误并尝试恢复。
- `canceling`：拒绝新 prompt，直到进入 `idle` 或 `error`。

### 4.3 AgentLoop

AgentLoop 不应假设“一次 prompt = 一次 LLM 调用”。标准循环：

```text
loop:
  reload session snapshot
  enforce single runner and max steps
  if canceled:
    mark current step/tool aborted
    break

  if pending permission:
    set run_state waiting_permission
    wait for permission reply
    continue

  if pending subtask:
    run subtask through typed Task tool
    append result part
    continue

  if context_overflow:
    create compaction step
    persist summary
    continue

  create assistant message
  create step
  build context through ContextBuilder
  stream model output into Processor

  if tool calls:
    execute through Tool Runtime
    append bounded tool result
    continue

  if finish stop:
    mark assistant completed
    break

set run_state idle | error | aborted
```

必须实现：

- `max_steps`。
- 相同 tool + 相同 input 的重复调用检测。
- cancel/abort 后不留下悬空 part。
- 每轮从存储重新读取必要上下文，避免只依赖内存状态。

## 5. RunState 设计

当前代码里已有 `Idle / Busy / Capturing / Canceling / Error`。Phase 9 应扩展为能表达用户体验的完整状态。

建议状态：

```text
idle
preparing
thinking
streaming
waiting_permission
running_tool
capturing
analyzing
reporting
compacting
retrying
canceling
completed
error
```

状态转移：

```text
idle
  -> preparing
  -> thinking
  -> streaming
  -> running_tool
  -> thinking
  -> completed
  -> idle

running_tool
  -> waiting_permission
  -> running_tool
  -> analyzing | reporting | capturing
  -> thinking

any running state
  -> canceling
  -> idle | error

any running state
  -> error
```

UI 显示策略：

| RunState | 用户可见含义 | 允许用户动作 |
| --- | --- | --- |
| `idle` | 可以输入新问题 | 输入、打开 pcap、生成报告 |
| `preparing` | 正在整理上下文 | 取消 |
| `thinking` | 正在请求模型 | 取消 |
| `streaming` | assistant 正在输出 | 取消 |
| `waiting_permission` | 等待用户批准/拒绝 | approve once / always / reject / reject with feedback |
| `running_tool` | 正在执行短工具 | 取消、查看进度 |
| `capturing` | 正在短时抓包 | 停止抓包、取消 |
| `analyzing` | 正在解析/检测 | 取消、查看 artifact |
| `reporting` | 正在生成报告 | 取消 |
| `compacting` | 正在压缩上下文 | 取消 |
| `retrying` | 正在按策略重试 | 取消 |
| `canceling` | 正在清理任务 | 等待 |
| `completed` | 本轮完成 | 继续输入 |
| `error` | 本轮失败但状态已收束 | 继续输入、查看错误 |

实现上可以把 `completed` 作为短暂事件状态，持久 Session 最终回到 `idle`。

## 6. Processor 设计

Processor 负责解释模型流式事件，不能让模型输出直接修改业务状态。

输入事件：

```text
reasoning.started
reasoning.delta
reasoning.ended
text.started
text.delta
text.ended
tool.input.started
tool.input.delta
tool.input.ended
tool.called
step.ended
step.failed
```

输出状态变化：

```text
create/update message part
emit message.part.updated
emit agent.text.delta
create tool_call part
enqueue Tool Runtime execution
mark assistant finish_reason
record token/cost metadata
```

关键规则：

- `text.delta` 只能追加到对应 text part。
- tool input stream 必须先累积并 schema validate，不能边流边执行。
- tool call 进入 Tool Runtime 前必须落库并发事件。
- step failed/aborted 必须同步 message、part、tool_call、session。

## 7. ContextBuilder 设计

网络数据上下文必须分层：

```text
Raw evidence
  pcap / tshark json / raw stdout / zeek logs / eve.json

Structured store
  flow / dns_event / tls_event / http_event / finding / artifact

Model-facing context
  bounded summary / selected evidence refs / top metrics / timeline / uncertainty
```

ContextBuilder 的输入：

```text
session snapshot
recent messages
compaction summaries
selected artifacts
structured findings
tool results
agent mode
permission/tool allowlist
token budget
```

ContextBuilder 的输出：

```text
system prompt
developer instructions
conversation messages
tool result messages
available tools
context budget report
```

规则：

- 不直接拼接 DB 原始历史。
- 不直接读取 artifact 原文塞给 LLM。
- 每条 finding 或 report 结论必须带 `EvidenceRef` 或 `ArtifactRef`。
- 上下文过长时创建 compaction step，而不是静默丢历史。
- summary 必须保留：用户目标、已执行操作、关键 evidence、失败尝试、当前待办、权限边界。

## 8. Agent Mode 与工具边界

Phase 9 应把 Agent Mode 从单一 `observe` 扩展为最小权限集合。

| Mode | 目标 | 工具范围 | 默认风险 |
| --- | --- | --- | --- |
| `observe` | 查看已有状态、flow、finding、artifact | list/status/summarize | low |
| `capture` | 申请短时抓包 | capture.start/status/stop | medium |
| `investigate` | 解析 pcap、检测异常 | pcap.open, tshark.extract_*, dns.detect_anomalies | medium |
| `report` | 生成报告和 IOC | report.generate, ioc.export | low |
| `respond` | 提出响应动作 | propose-only，禁止默认执行 | high |

必须遵守：

- Mode 绑定 tool allowlist。
- Mode 绑定 max steps。
- Mode 绑定 permission ruleset。
- `respond` 阶段只能生成建议和风险说明，除非后续规格明确实现响应工具和高危确认链路。

## 9. UI 交互模型

UI 应呈现“任务正在推进”的结构化状态，而不是仅显示一段聊天文本。

### 9.1 主屏布局

最小有效布局：

```text
Top status bar:
  Core ready / Session / RunState / Mode / Active artifact

Left:
  Cases or Session timeline

Center:
  Agent conversation
  Message parts:
    text
    reasoning collapsed
    tool call card
    permission card
    artifact/finding/report refs

Right:
  Evidence panel
  Findings
  Capture/report status

Bottom:
  Prompt input
  Contextual actions
```

### 9.2 MessagePart 渲染

| Part | UI 表达 |
| --- | --- |
| `text` | assistant 正文，支持 streaming |
| `reasoning` | 折叠块，显示正在分析/已完成 |
| `tool_call` | 工具名、参数摘要、状态、进度 |
| `tool_result` | 结果摘要、artifact refs、是否截断 |
| `permission` | 风险、原因、命令预览、四种回复 |
| `artifact_ref` | 可打开的证据引用，不展开大内容 |
| `finding_ref` | finding 摘要、严重度、证据 |
| `report_ref` | 报告路径、metadata、导出动作 |
| `error` | 错误信息、可恢复建议 |

### 9.3 权限体验

权限卡必须展示：

```text
tool
reason
risk
scope/pattern
command_preview
timeout
artifact destination
```

用户动作：

- `Allow once`：只允许当前 call。
- `Always allow pattern`：持久化当前 pattern。
- `Reject`：拒绝并停止当前危险动作。
- `Reject with feedback`：拒绝并把用户反馈回灌给 assistant 重新规划。

UI 禁止：

- 自己拼接 `tcpdump` 命令。
- 自己判断 always rule 是否命中。
- 在 pending permission 未解决时覆盖当前 step。

### 9.4 失败和取消体验

取消流程：

```text
User cancel
  -> UI 调用 agent.abort 或 capture.stop
  -> Core 设置 cancel token
  -> Tool Runtime 停止子进程/任务
  -> ToolCall -> aborted
  -> Step -> aborted
  -> Session -> idle 或 error
  -> UI 显示已取消和已保存 artifact
```

失败流程：

```text
Tool/Model error
  -> part.error
  -> step.failed
  -> session.error
  -> assistant 生成可恢复说明或等待用户下一步
```

错误信息必须包含：

- 失败位置：model / tool / permission / artifact / storage / harness。
- 是否产生 artifact。
- 用户可做的下一步。

## 10. 事件协议补充

现有事件应扩展为 message/part 粒度，便于 UI 恢复和细粒度渲染。

Agent Session Events：

```text
session.created
session.updated
session.run_state.changed
message.created
message.updated
message.part.created
message.part.updated
message.part.delta
agent.step.started
agent.step.ended
agent.step.failed
agent.tool.called
agent.tool.progress
agent.tool.success
agent.tool.failed
agent.tool.aborted
permission.asked
permission.replied
session.compaction.started
session.compaction.ended
session.error
```

Network Domain Events 保持分层：

```text
capture.started
capture.stopped
pcap.created
packet.sampled
flow.created
flow.updated
dns.observed
finding.created
finding.updated
artifact.created
report.generated
```

事件 envelope：

```json
{
  "id": "evt_001",
  "type": "message.part.updated",
  "timestamp": "2026-06-04T00:00:00Z",
  "cursor": "cur_001",
  "aggregate": {
    "session_id": "ses_001",
    "message_id": "msg_001",
    "part_id": "part_001"
  },
  "payload": {}
}
```

Harness 要求：

- 支持 event batching。
- 支持 reconnect cursor 或 recent snapshot。
- 支持 backpressure，避免高频 flow/packet 事件淹没 UI。
- 只转发事件和状态，不承载业务逻辑。

## 11. RPC/API 设计建议

Phase 9 最小 API：

```text
session.create
session.get
session.list
session.cancel
agent.ask
agent.abort
message.list
permission.list_pending
permission.reply
artifact.list
artifact.get_summary
```

`agent.ask` 输入：

```json
{
  "session_id": "optional",
  "case_id": "optional",
  "mode": "observe",
  "input": {
    "parts": [
      { "kind": "text", "text": "帮我分析这个 pcap" },
      { "kind": "artifact_ref", "artifact_id": "art_001" }
    ]
  },
  "options": {
    "no_reply": false,
    "max_steps": 8
  }
}
```

`agent.ask` 输出：

```json
{
  "session_id": "ses_001",
  "user_message_id": "msg_user_001",
  "assistant_message_id": "msg_asst_001",
  "run_state": "idle",
  "final_summary": "已完成分析，发现 1 个 NXDOMAIN spike。",
  "artifact_refs": [],
  "finding_refs": ["finding_001"]
}
```

冲突错误：

```json
{
  "code": "session_busy",
  "message": "Session is waiting for permission.",
  "details": {
    "session_id": "ses_001",
    "run_state": "waiting_permission",
    "pending_permission_ids": ["per_001"]
  }
}
```

## 12. 存储与恢复

必须能从存储恢复：

```text
sessions
messages
message_parts
steps
tool_calls
permission_requests
artifacts
findings
event_cursor
```

恢复规则：

- Core 重启后，`running_tool/capturing/analyzing/reporting` 状态必须被检查并收束为 `error`、`aborted` 或恢复为 BackgroundJob。
- pending permission 可以恢复并重新发 `permission.asked` snapshot。
- UI 重连后先拉 snapshot，再应用 cursor 后事件。
- orphan artifact 可以进入 artifact inventory，但必须标记来源不完整。

## 13. 防跑偏实现顺序

Phase 9 建议按以下最小 deliverable 推进：

1. 补 `Session/Message/MessagePart` 持久化字段和 RPC snapshot。
2. 让 `agent.ask` 支持 session create/append，而不是每次 mock turn 自成一轮。
3. 引入 `message.part.*` 事件，UI 按 part 渲染。
4. 把 ToolCall 与 MessagePart 绑定，保证 `pending -> running -> completed/error/aborted` 可恢复。
5. 扩展 RunState 到 `waiting_permission/running_tool/analyzing/reporting/compacting`。
6. 实现 ContextBuilder skeleton，只返回有界 summary 和 evidence refs。
7. 加 max steps 和重复 tool-call doom-loop 检测。
8. 补 UI 恢复 snapshot 和 pending permission 恢复。

每一步都必须有单独验收，不允许一次性改成大型 UI 或真实外部能力。

## 14. 验收标准

Phase 9 通过条件：

- 第一次 `agent.ask` 会创建 session、user message、assistant message 和 message parts。
- 后续 `agent.ask` 能追加到同一 session。
- UI 能展示 text streaming、tool call、tool result、permission、artifact/finding refs。
- ToolCall 状态可从事件和 snapshot 恢复。
- pending permission 在 UI 重连或 Core 状态查询后仍可见。
- cancel 后 running step/tool 不悬空。
- 模型上下文只包含 bounded summary、structured facts、ArtifactRef/EvidenceRef。
- 重复相同 tool + input 超过阈值会停止或请求用户确认。
- 大输出和原始证据不进入 UI activity stream 或 LLM context。

## 15. 实现 agent 固定工作提示

后续实现本文相关内容时，agent 必须先执行：

```text
1. 阅读 netagent_build_spec.md 第 20/21 节。
2. 阅读 user-assistant-interaction-design.md。
3. 从 HANDOFF.md 判断当前 Phase。
4. 只选择当前 Phase 的最小 deliverable。
5. 明确不触碰真实抓包、Zeek、Suricata、外部情报、防火墙响应或大型 UI，除非当前 gate 明确允许。
```

每轮结束必须报告：

```text
Current phase
Files changed
Verification commands and results
Checks not run and why
Whether any anti-drift rule was triggered
Next phase or next gate
```

## 16. 反跑偏清单

出现以下情况必须停止：

- UI 或 Harness 直接执行 `tcpdump`、`tshark`、`pfctl`、`iptables`。
- assistant 生成任意 shell 作为执行接口，而不是 typed Tool API。
- ToolResult 把大 stdout、tshark JSON、pcap 内容直接给 LLM。
- 没有 PermissionRequest 状态机就新增危险工具。
- 没有 timeout/cancel 就新增长任务。
- 没有 ArtifactRef 就处理大文件或原始证据。
- 修改协议但不更新 schema、事件说明和 UI state。
- 为了演示体验绕过权限确认。
- 先做大型界面重构，而 session/message/part/RunState 还不可恢复。

## 17. 一句话原则

NetAgent 的 assistant 交互应把用户意图、模型输出、工具执行、权限审批、证据引用和 UI 展示全部落到稳定的状态机里。用户看到的是清晰推进的调查过程；实现 agent 看到的是不可跳过的阶段闸门和可验收的最小闭环。
