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
  describeWorkspace,
  initialState,
} from "./state"
import { ApprovalModal } from "../components/approval_modal"
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

  const recentEvents = useMemo(() => state.events.slice(-8).reverse(), [state.events])
  const recentMessages = useMemo(
    () => state.session.messages.slice(-8),
    [state.session.messages],
  )
  const findings = useMemo(() => state.alerts.slice(-4).reverse(), [state.alerts])

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
        title={describeWorkspace()}
        mode={viewMode}
        sync={state.sync}
        session={state.session}
        snapshot={state.dashboard}
        pendingCount={state.permission.pending.length}
      />

      <box flexDirection="row" gap={1} flexGrow={1}>
        <box
          width="34%"
          flexDirection="column"
          borderStyle="single"
          borderColor="#334155"
          padding={1}
          gap={1}
        >
          <text fg="#cbd5e1">Dashboard</text>
          <PanelLine label="Protocol" value={state.dashboard.protocolVersion} />
          <PanelLine label="Methods" value={String(state.dashboard.methodCount)} />
          <PanelLine label="Events" value={String(state.dashboard.eventCount)} />
          <PanelLine label="Interfaces" value={state.dashboard.interfaces.join(", ")} />
          <PanelLine label="RunState" value={state.dashboard.runState} />
          <PanelLine label="Capture" value={state.capture.status} />
          <PanelLine label="CaptureId" value={state.capture.captureId} />
          <PanelLine label="Interface" value={state.capture.captureInterface} />
          <PanelLine label="Session" value={state.session.sessionId} />
          <PanelLine label="Pending" value={String(state.permission.pending.length)} />
          <PanelLine label="Findings" value={String(state.alerts.length)} />
          {state.sync.status === "error" ? (
            <PanelLine label="SyncError" value={state.sync.error ?? "unknown"} />
          ) : null}

          <box marginTop={1} flexDirection="column" gap={1}>
            <text fg="#cbd5e1">Alerts</text>
            {findings.length === 0 ? (
              <text fg="#64748b">No findings yet.</text>
            ) : (
              findings.map((finding: AlertItem) => (
                <box key={finding.id} flexDirection="column">
                  <text fg={severityColor(finding.severity)}>
                    {finding.severity.toUpperCase()} {finding.title}
                  </text>
                  <text fg="#94a3b8">{finding.summary}</text>
                </box>
              ))
            )}
          </box>
        </box>

        <box
          width="66%"
          flexDirection="column"
          borderStyle="single"
          borderColor="#334155"
          padding={1}
          gap={1}
        >
          <text fg="#cbd5e1">Activity</text>
          <box flexDirection="column" flexGrow={1} gap={1}>
            {recentEvents.map((event: CoreEvent, index: number) => (
              <box key={`${event.method}-${index}`} flexDirection="column">
                <text fg="#f8fafc">{event.method}</text>
                <text fg="#64748b">{truncate(JSON.stringify(event.params), 96)}</text>
              </box>
            ))}
          </box>

          <box
            flexDirection="column"
            borderStyle="single"
            borderColor="#1e293b"
            padding={1}
            gap={1}
          >
            <text fg="#cbd5e1">Agent Chat</text>
            <box flexDirection="column" gap={1}>
              {recentMessages.map((message) => (
                <box key={message.id} flexDirection="column">
                  <text fg={chatRoleColor(message.role, message.status)}>
                    {chatRoleLabel(message.role, message.status)}
                  </text>
                  <text fg="#e2e8f0">{truncate(message.content, 320)}</text>
                </box>
              ))}
            </box>
            <box
              borderStyle="single"
              borderColor={canSubmitPrompt(state) ? "#0f766e" : "#facc15"}
              padding={1}
            >
              <text fg={state.session.chatInput ? "#e2e8f0" : "#64748b"}>
                {state.session.chatInput || "Ask NetAgent..."}
              </text>
            </box>
            <text fg="#64748b">
              Enter send | Backspace edit | Ctrl+R refresh | Esc quit
            </text>
          </box>
        </box>
      </box>

      <ApprovalModal
        request={state.permission.pending[0]}
        visible={state.permission.pending.length > 0}
      />
    </box>
  )

  function PanelLine(props: { label: string; value: string }) {
    return (
      <box flexDirection="row" justifyContent="space-between">
        <text fg="#64748b">{props.label}</text>
        <text fg="#e2e8f0">{props.value}</text>
      </box>
    )
  }
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

function chatRoleLabel(
  role: "user" | "assistant" | "system",
  status: "sending" | "sent" | "error",
): string {
  if (status === "error") return `${role} error`
  if (role === "user") return "you"
  if (role === "assistant") return "netagent"
  return "system"
}

function chatRoleColor(
  role: "user" | "assistant" | "system",
  status: "sending" | "sent" | "error",
): string {
  if (status === "error") return "#f97316"
  if (role === "user") return "#38bdf8"
  if (role === "assistant") return "#34d399"
  return "#94a3b8"
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
