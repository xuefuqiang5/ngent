import { useEffect, useMemo, useState } from "react"
import type { KeyEvent } from "@opentui/core"
import { useKeyboard, useRenderer } from "@opentui/react"
import type { CoreEvent } from "../harness/event_router"
import type { RpcClient } from "../harness/rpc_client"
import type { StdioTransport } from "../harness/transport"
import type {
  AlertItem,
  AppState,
  CaptureState,
  DashboardSnapshot,
  PendingApproval,
} from "./state"
import {
  canSubmitPrompt,
  deriveViewMode,
  initialState,
} from "./state"
import { StatusBar } from "../components/status_bar"

type AppProps = {
  eventRouter: {
    listEvents(): CoreEvent[]
    onEvent(listener: (event: CoreEvent) => void): () => void
  }
  rpc: RpcClient
  transport: StdioTransport
}

export function App({ eventRouter, rpc, transport }: AppProps) {
  const renderer = useRenderer()
  const [state, setState] = useState<AppState>(initialState())
  const viewMode = deriveViewMode(state)

  useEffect(() => {
    let mounted = true

    const unsubscribe = eventRouter.onEvent((event) => {
      if (!mounted) return
      setState((current: AppState) => reduceEvent(current, event))
    })

    void hydrate()

    return () => {
      mounted = false
      unsubscribe()
      void transport.close()
    }
  }, [eventRouter, rpc, transport])

  useEffect(() => {
    if (state.sync.status !== "ready") return
    const interval = setInterval(() => {
      void refreshCaptureStatus()
    }, 1000)
    return () => clearInterval(interval)
  }, [state.sync.status])

  useKeyboard((event) => {
    if (event.eventType === "release") return

    if (event.name === "escape" || (event.ctrl && event.name === "c")) {
      renderer.destroy()
      return
    }

    if (event.ctrl && event.name === "r") {
      void hydrate()
      return
    }

    if (state.permission.pending.length > 0) {
      if (event.name === "y") {
        void replyToPermission("once")
        return
      }
      if (event.name === "a") {
        void replyToPermission("always")
        return
      }
      if (event.name === "n") {
        void replyToPermission("reject")
        return
      }
      if (event.name === "f") {
        void replyToPermission("reject_with_feedback")
        return
      }
      return
    }

    if (event.name === "return") {
      if (canSubmitPrompt(state)) void sendAgentPrompt()
      return
    }

    setState((current: AppState) => ({
      ...current,
      session: {
        ...current.session,
        chatInput: applyChatInputKey(current.session.chatInput, event),
      },
    }))
  })

  const recentMessages = useMemo(
    () => state.session.messages.slice(-8),
    [state.session.messages],
  )
  const workTrace = useMemo(
    () => state.events.map(summarizeCoreEvent).filter(isTraceItem).slice(-6),
    [state.events],
  )
  const findings = useMemo(() => state.alerts.slice(-3).reverse(), [state.alerts])

  async function hydrate(): Promise<void> {
    setState((current: AppState) => ({
      ...current,
      sync: { status: "syncing" },
    }))

    try {
      const [capabilities, interfaces, pending] = await Promise.all([
        rpc.request("core.capabilities"),
        rpc.request("system.list_interfaces"),
        rpc.request("permission.list_pending"),
      ])
      const captureStatus = await rpc.request("capture.status")

      setState((current: AppState) => ({
        ...current,
        sync: { status: "ready" },
        dashboard: buildSnapshot(capabilities, interfaces),
        capture: readCaptureSnapshot(captureStatus),
        permission: {
          ...current.permission,
          pending: readPending(pending),
        },
        session: {
          ...current.session,
          messages: markSystemMessage(
            current.session.messages,
            "Core connected. Continue the session or ask a new question.",
          ),
        },
      }))
    } catch (error) {
      setState((current: AppState) => ({
        ...current,
        sync: {
          status: "error",
          error: error instanceof Error ? error.message : String(error),
        },
        session: {
          ...current.session,
          status: "idle",
          messages: [
            ...current.session.messages,
            {
              id: nextUiId("chat_error"),
              role: "system",
              status: "error",
              content: error instanceof Error ? error.message : String(error),
            },
          ],
        },
      }))
    }
  }

  async function sendAgentPrompt(): Promise<void> {
    const prompt = state.session.chatInput.trim()
    if (!prompt || !canSubmitPrompt(state)) return

    const userMessageId = nextUiId("chat_user")
    setState((current: AppState) => ({
      ...current,
      session: {
        ...current.session,
        status: "busy",
        chatInput: "",
        lastPrompt: prompt,
        messages: [
          ...current.session.messages,
          {
            id: userMessageId,
            role: "user",
            status: "sent",
            content: prompt,
          },
        ],
      },
    }))

    try {
      const result = await rpc.request("agent.ask", {
        session_id: state.session.sessionId === "n/a" ? undefined : state.session.sessionId,
        input: prompt,
      })
      const response = result as {
        session?: { id?: string }
        assistant_message?: { id?: string; parts?: Array<{ content?: string }> }
      }
      const assistantText = response.assistant_message?.parts?.[0]?.content

      setState((current: AppState) => ({
        ...current,
        session: {
          ...current.session,
          status: "idle",
          sessionId: response.session?.id ?? current.session.sessionId,
          lastAgentResult: assistantText ?? JSON.stringify(result),
          messages: [
            ...current.session.messages,
            {
              id: response.assistant_message?.id ?? nextUiId("chat_assistant"),
              role: "assistant",
              status: "sent",
              content: assistantText ?? JSON.stringify(result),
            },
          ],
        },
      }))
    } catch (error) {
      setState((current: AppState) => ({
        ...current,
        session: {
          ...current.session,
          status: "retry",
          chatInput: prompt,
          messages: [
            ...current.session.messages,
            {
              id: nextUiId("chat_error"),
              role: "assistant",
              status: "error",
              content: error instanceof Error ? error.message : String(error),
            },
          ],
        },
      }))
    }
  }

  async function replyToPermission(
    decision: "once" | "always" | "reject" | "reject_with_feedback",
  ): Promise<void> {
    const request = state.permission.pending[0]
    if (!request || state.permission.replying) return

    setState((current: AppState) => ({
      ...current,
      permission: {
        ...current.permission,
        replying: request.id,
      },
    }))

    try {
      await rpc.request("permission.reply", {
        request_id: request.id,
        decision,
        feedback:
          decision === "reject_with_feedback"
            ? "Use a shorter duration and limit to dns."
            : undefined,
      })

      const pending = await rpc.request("permission.list_pending")
      setState((current: AppState) => ({
        ...current,
        permission: {
          pending: readPending(pending),
        },
      }))
      await refreshCaptureStatus()
    } finally {
      setState((current: AppState) => ({
        ...current,
        permission: {
          ...current.permission,
          replying:
            current.permission.replying === request.id
              ? undefined
              : current.permission.replying,
        },
      }))
    }
  }

  async function refreshCaptureStatus(): Promise<void> {
    const payload = await rpc.request("capture.status")
    setState((current: AppState) => ({
      ...current,
      capture: readCaptureSnapshot(payload),
    }))
  }

  return (
    <box
      flexDirection="column"
      width="100%"
      height="100%"
      backgroundColor="#111318"
      padding={1}
      gap={1}
    >
      <StatusBar
        mode={viewMode}
        sync={state.sync}
        session={state.session}
        snapshot={state.dashboard}
        capture={state.capture}
        pendingCount={state.permission.pending.length}
      />

      <box
        flexDirection="column"
        flexGrow={1}
        borderStyle="single"
        borderColor="#1f2937"
        padding={1}
        gap={1}
      >
        <box flexDirection="column" flexGrow={1} gap={1}>
          {recentMessages.map((message) => (
            <ThreadMessage key={message.id} message={message} />
          ))}

          {workTrace.length > 0 ? (
            <box flexDirection="column" marginTop={1} gap={0}>
              {workTrace.map((item, index) => (
                <TraceLine key={`${item.title}-${index}`} item={item} />
              ))}
            </box>
          ) : null}

          <InlinePermissionCard request={state.permission.pending[0]} />

          <FindingsStrip findings={findings} totalCount={state.alerts.length} />

          {state.sync.status === "error" ? (
            <box flexDirection="column" marginTop={1}>
              <text fg="#f97316">Core unavailable</text>
              <text fg="#94a3b8">{truncate(state.sync.error ?? "unknown error", 120)}</text>
            </box>
          ) : null}
        </box>

        <box flexDirection="column" marginTop={1} gap={1}>
          <Composer state={state} />
          <text fg="#4b5563">
            Enter send · Backspace edit · Ctrl+R refresh · Esc quit
          </text>
        </box>
      </box>
    </box>
  )
}

export function applyChatInputKey(value: string, event: KeyEvent): string {
  if (event.ctrl || event.meta) return value
  if (event.name === "backspace") return value.slice(0, -1)
  if (event.name === "delete") return value.slice(0, -1)
  if (event.name === "space") return `${value} `
  if (event.name === "tab") return `${value}  `
  if (event.name.length === 1) {
    return `${value}${event.shift ? event.name.toUpperCase() : event.name}`
  }

  const sequence = event.sequence ?? ""
  if (sequence.length > 0 && !sequence.startsWith("\u001b") && sequence >= " ") {
    return `${value}${sequence}`
  }
  return value
}

function markSystemMessage(messages: AppState["session"]["messages"], content: string) {
  const [first, ...rest] = messages
  if (first?.role !== "system") {
    return [
      {
        id: "chat_system_0001",
        role: "system" as const,
        status: "sent" as const,
        content,
      },
      ...messages,
    ]
  }
  return [{ ...first, status: "sent" as const, content }, ...rest]
}

function ThreadMessage(props: {
  message: AppState["session"]["messages"][number]
}) {
  if (props.message.role === "user") {
    return (
      <box flexDirection="column" marginBottom={1}>
        <text fg="#e5e7eb">{`> ${truncate(props.message.content, 220)}`}</text>
      </box>
    )
  }

  if (props.message.status === "error") {
    return (
      <box flexDirection="column" marginBottom={1}>
        <text fg="#f97316">error</text>
        <text fg="#d1d5db">{truncate(props.message.content, 260)}</text>
      </box>
    )
  }

  if (props.message.role === "system") {
    return (
      <box flexDirection="column" marginBottom={1}>
        <text fg="#6b7280">{truncate(props.message.content, 220)}</text>
      </box>
    )
  }

  return (
    <box flexDirection="column" marginBottom={1}>
      <text fg="#e2e8f0">{truncate(props.message.content, 420)}</text>
    </box>
  )
}

type TraceItem = {
  title: string
  detail?: string
  status?: "running" | "done" | "error" | "pending"
}

function isTraceItem(item: TraceItem | null): item is TraceItem {
  return item !== null
}

function TraceLine(props: { item: TraceItem }) {
  return (
    <box flexDirection="column" marginBottom={1}>
      <text fg="#94a3b8">{props.item.title}</text>
      {props.item.detail ? (
        <text fg={traceStatusColor(props.item.status)}>
          {`  ${traceStatusLabel(props.item.status)}${props.item.detail}`}
        </text>
      ) : null}
    </box>
  )
}

function Composer(props: { state: AppState }) {
  const canSubmit = canSubmitPrompt(props.state)
  const input = props.state.session.chatInput
  const text = input || (canSubmit ? "Ask NetAgent..." : blockedReason(props.state))

  return (
    <box
      borderStyle="single"
      borderColor={canSubmit ? "#334155" : "#b45309"}
      paddingX={1}
      paddingY={0}
    >
      <text fg={input ? "#e5e7eb" : canSubmit ? "#6b7280" : "#d97706"}>
        {`> ${text}`}
      </text>
    </box>
  )
}

function InlinePermissionCard(props: { request?: PendingApproval }) {
  if (!props.request) return null

  return (
    <box
      flexDirection="column"
      marginTop={1}
      marginBottom={1}
      borderStyle="single"
      borderColor="#b45309"
      padding={1}
      gap={1}
    >
      <text fg="#f59e0b">
        {`permission required · ${props.request.risk} risk`}
      </text>
      <text fg="#e5e7eb">{props.request.metadata.tool}</text>
      <text fg="#cbd5e1">{truncate(props.request.metadata.reason, 180)}</text>
      {props.request.patterns.length > 0 ? (
        <text fg="#94a3b8">
          {`scope: ${truncate(props.request.patterns.join(" "), 160)}`}
        </text>
      ) : null}
      <text fg="#94a3b8">
        {`preview: ${truncate(props.request.metadata.command_preview, 180)}`}
      </text>
      <text fg="#d97706">[Y] once   [A] always   [N] reject   [F] feedback</text>
    </box>
  )
}

function FindingsStrip(props: { findings: AlertItem[]; totalCount: number }) {
  if (props.totalCount === 0) {
    return <text fg="#4b5563">Findings: none</text>
  }

  const latest = props.findings[0]
  const summary = latest
    ? `${latest.severity} · ${latest.title}`
    : `${props.totalCount} findings`

  return (
    <text fg={latest ? severityColor(latest.severity) : "#94a3b8"}>
      {`Findings: ${props.totalCount} · latest: ${truncate(summary, 120)}`}
    </text>
  )
}

export function summarizeCoreEvent(event: CoreEvent): TraceItem | null {
  if (event.method === "agent.step.started") {
    return {
      title: "Thinking through request",
      detail: "step running",
      status: "running",
    }
  }

  if (event.method === "agent.step.ended") {
    return {
      title: "Finishing response",
      detail: "step completed",
      status: "done",
    }
  }

  if (event.method === "agent.tool.called") {
    return {
      title: "Running tool",
      detail: readToolName(event.params),
      status: "running",
    }
  }

  if (event.method === "agent.tool.progress") {
    return {
      title: "Tool progress",
      detail: getString(event.params, "message") ?? "running",
      status: "running",
    }
  }

  if (event.method === "agent.tool.success") {
    return {
      title: "Tool completed",
      detail: readToolName(event.params),
      status: "done",
    }
  }

  if (event.method === "capture.started") {
    return {
      title: "Starting live capture",
      detail: formatCaptureScope(event.params),
      status: "running",
    }
  }

  if (event.method === "capture.stopped") {
    return {
      title: "Capture stopped",
      detail: getString(event.params, "reason") ?? "stopped",
      status: "done",
    }
  }

  if (event.method === "finding.created") {
    const finding = normalizeFinding(event.params)
    return {
      title: "Finding recorded",
      detail: `${finding.severity} · ${finding.title}`,
      status: "done",
    }
  }

  if (event.method === "artifact.created" || event.method === "pcap.created") {
    return {
      title: "Evidence artifact recorded",
      detail: readArtifactLabel(event.params),
      status: "done",
    }
  }

  return null
}

function blockedReason(state: AppState): string {
  if (state.permission.pending.length > 0) return "Permission required; choose Y/A/N/F"
  if (state.sync.status === "error") return "Core unavailable; Ctrl+R to retry"
  if (state.sync.status === "syncing") return "Core is syncing"
  if (state.session.status === "busy") return "Agent is responding"
  return "Ask NetAgent..."
}

function traceStatusLabel(status: TraceItem["status"]): string {
  if (status === "running") return "running: "
  if (status === "done") return "done: "
  if (status === "error") return "failed: "
  if (status === "pending") return "pending: "
  return ""
}

function traceStatusColor(status: TraceItem["status"]): string {
  if (status === "running") return "#94a3b8"
  if (status === "done") return "#6ee7b7"
  if (status === "error") return "#f97316"
  if (status === "pending") return "#f59e0b"
  return "#94a3b8"
}

function readToolName(params: unknown): string {
  return (
    getString(params, "tool_name") ??
    getString((params as { tool_call?: unknown }).tool_call, "tool_name") ??
    "tool"
  )
}

function formatCaptureScope(params: unknown): string {
  const iface = getString(params, "interface") ?? "interface n/a"
  const duration = getNumber(params, "duration_secs")
  const filter = getString(params, "filter")
  return [
    `iface=${iface}`,
    filter ? `filter=${filter}` : undefined,
    duration ? `duration=${duration}s` : undefined,
  ]
    .filter(Boolean)
    .join(" ")
}

function readArtifactLabel(params: unknown): string {
  const artifact = (params as { artifact?: unknown }).artifact
  return (
    getString(artifact, "id") ??
    getString(artifact, "path") ??
    getString(params, "capture_id") ??
    "artifact"
  )
}

function getString(params: unknown, key: string): string | undefined {
  const value = (params as Record<string, unknown> | undefined)?.[key]
  return typeof value === "string" ? value : undefined
}

function getNumber(params: unknown, key: string): number | undefined {
  const value = (params as Record<string, unknown> | undefined)?.[key]
  return typeof value === "number" ? value : undefined
}

function nextUiId(prefix: string): string {
  return `${prefix}_${Date.now()}_${Math.floor(Math.random() * 10000)}`
}

function buildSnapshot(capabilities: unknown, interfaces: unknown): DashboardSnapshot {
  const caps = capabilities as {
    protocol_version?: string
    methods?: unknown[]
    events?: unknown[]
    phase?: string
  }
  const network = interfaces as { interfaces?: Array<{ name?: string }> }

  return {
    protocolVersion: caps.protocol_version ?? "2.0",
    methodCount: caps.methods?.length ?? 0,
    eventCount: caps.events?.length ?? 0,
    interfaces: (network.interfaces ?? []).map((item) => item.name ?? "unknown"),
    runState: caps.phase ?? "unknown",
  }
}

function readCaptureSnapshot(payload: unknown): CaptureState {
  const capture = payload as {
    status?: string
    capture_id?: string
    interface?: string
  }

  return {
    status: capture.status ?? "idle",
    captureId: capture.capture_id ?? "n/a",
    captureInterface: capture.interface ?? "n/a",
  }
}

function readPending(payload: unknown): PendingApproval[] {
  const pending = (payload as { pending?: PendingApproval[] }).pending
  return pending ?? []
}

export function reduceEvent(current: AppState, event: CoreEvent): AppState {
  const next = { ...current, events: [...current.events, event] }

  if (event.method === "permission.asked") {
    const request = (event.params as { request?: PendingApproval }).request
    if (!request) return next
    return {
      ...next,
      permission: {
        ...current.permission,
        pending: [...current.permission.pending, request],
      },
    }
  }

  if (event.method === "permission.replied") {
    const requestId = (event.params as { request_id?: string }).request_id
    if (!requestId) return next
    return {
      ...next,
      permission: {
        ...current.permission,
        pending: current.permission.pending.filter((item) => item.id !== requestId),
        replying:
          current.permission.replying === requestId
            ? undefined
            : current.permission.replying,
      },
    }
  }

  if (event.method === "finding.created") {
    const finding = normalizeFinding(event.params)
    return {
      ...next,
      alerts: [
        ...current.alerts.filter((item) => item.id !== finding.id),
        finding,
      ],
    }
  }

  if (event.method === "capture.started") {
    const payload = event.params as {
      capture_id?: string
      interface?: string
    }
    return {
      ...next,
      capture: {
        status: "running",
        captureId: payload.capture_id ?? next.capture.captureId,
        captureInterface: payload.interface ?? next.capture.captureInterface,
      },
    }
  }

  if (event.method === "capture.stopped") {
    return {
      ...next,
      capture: {
        ...next.capture,
        status: "stopped",
      },
    }
  }

  return next
}

export function normalizeFinding(payload: unknown): AlertItem {
  const envelope = payload as {
    finding?: unknown
  }
  const finding = (envelope.finding ?? payload) as {
    id?: string
    severity?: string
    title?: string
    summary?: string
    description?: string
  }

  return {
    id: finding.id ?? `finding-${Date.now()}`,
    severity: finding.severity ?? "low",
    title: finding.title ?? "Unknown finding",
    summary: finding.summary ?? finding.description ?? "No summary",
  }
}

function severityColor(severity: string): string {
  if (severity === "high") return "#f97316"
  if (severity === "medium") return "#facc15"
  return "#38bdf8"
}

function truncate(value: string, max: number): string {
  if (value.length <= max) return value
  return `${value.slice(0, max)}...`
}
