import { useEffect, useMemo, useState } from "react"
import { useKeyboard, useRenderer } from "@opentui/react"
import type { CoreEvent } from "../harness/event_router"
import type { RpcClient } from "../harness/rpc_client"
import type { StdioTransport } from "../harness/transport"
import type {
  AlertItem,
  DashboardSnapshot,
  PendingApproval,
  UiMode,
  UiState,
} from "./state"
import { describeWorkspace, initialState } from "./state"
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

const PROMPTS = [
  "Summarize the current mock network posture.",
  "Focus on top DNS talkers and protocol mix.",
  "Explain the latest finding and point to evidence.",
]

export function App({ eventRouter, rpc, transport }: AppProps) {
  const renderer = useRenderer()
  const [state, setState] = useState<UiState>(initialState())

  useEffect(() => {
    let mounted = true

    const unsubscribe = eventRouter.onEvent((event) => {
      if (!mounted) return
      setState((current: UiState) => reduceEvent(current, event))
    })

    void hydrate()
    const interval = setInterval(() => {
      void refreshCaptureStatus()
    }, 1000)

    return () => {
      mounted = false
      clearInterval(interval)
      unsubscribe()
      void transport.close()
    }
  }, [eventRouter, rpc, transport])

  useKeyboard((event) => {
    if (event.eventType === "release") return

    if (event.name === "q" || event.name === "escape") {
      renderer.destroy()
      return
    }

    if (event.name === "tab") {
      setState((current: UiState) => ({
        ...current,
        selectedPromptIndex: (current.selectedPromptIndex + 1) % PROMPTS.length,
      }))
      return
    }

    if (event.name === "return") {
      void sendAgentPrompt()
      return
    }

    if (event.name === "c") {
      void requestCapture()
      return
    }

    if (event.name === "x") {
      void stopCapture()
      return
    }

    if (event.name === "r") {
      void hydrate()
      return
    }

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
    }
  }, { release: true })

  const selectedPrompt = PROMPTS[state.selectedPromptIndex] ?? PROMPTS[0]
  const recentEvents = useMemo(() => state.events.slice(-10).reverse(), [state.events])
  const findings = useMemo(() => state.alerts.slice(-4).reverse(), [state.alerts])

  async function hydrate(): Promise<void> {
    setState((current: UiState) => ({ ...current, loading: true, mode: "syncing" }))

    const [capabilities, interfaces, pending] = await Promise.all([
      rpc.request("core.capabilities"),
      rpc.request("system.list_interfaces"),
      rpc.request("permission.list_pending"),
    ])
    const captureStatus = await rpc.request("capture.status")

    setState((current: UiState) => ({
      ...current,
      loading: false,
      mode: current.pending.length > 0 ? "approval" : "dashboard",
      snapshot: buildSnapshot(capabilities, interfaces, captureStatus),
      pending: readPending(pending),
    }))
  }

  async function sendAgentPrompt(): Promise<void> {
    setState((current: UiState) => ({
      ...current,
      mode: "agent",
      loading: true,
      lastPrompt: selectedPrompt,
    }))
    const result = await rpc.request("agent.ask", { input: selectedPrompt })

    setState((current: UiState) => ({
      ...current,
      loading: false,
      mode: current.pending.length > 0 ? "approval" : "agent",
      lastAgentResult: JSON.stringify(result),
    }))
  }

  async function requestCapture(): Promise<void> {
    setState((current: UiState) => ({ ...current, loading: true, mode: "approval" }))
    await rpc.request("capture.start", {
      session_id: "ses_ui_capture",
      interface: "mock1",
      filter: "tcp or dns",
      duration: 30,
    })

    const pending = await rpc.request("permission.list_pending")
    setState((current: UiState) => ({
      ...current,
      loading: false,
      mode: "approval",
      pending: readPending(pending),
    }))
    await refreshCaptureStatus()
  }

  async function stopCapture(): Promise<void> {
    setState((current: UiState) => ({ ...current, loading: true }))
    await rpc.request("capture.stop")
    await refreshCaptureStatus()
    setState((current: UiState) => ({ ...current, loading: false }))
  }

  async function replyToPermission(
    decision: "once" | "always" | "reject" | "reject_with_feedback",
  ): Promise<void> {
    const request = state.pending[0]
    if (!request) return

    setState((current: UiState) => ({ ...current, loading: true }))
    await rpc.request("permission.reply", {
      request_id: request.id,
      decision,
      feedback:
        decision === "reject_with_feedback"
          ? "Use a shorter duration and limit to dns."
          : undefined,
    })

    const pending = await rpc.request("permission.list_pending")
    setState((current: UiState) => ({
      ...current,
      loading: false,
      mode: readPending(pending).length > 0 ? "approval" : "dashboard",
      pending: readPending(pending),
    }))
    await refreshCaptureStatus()
  }

  async function refreshCaptureStatus(): Promise<void> {
    const payload = await rpc.request("capture.status")
    setState((current: UiState) => ({
      ...current,
      snapshot: {
        ...current.snapshot,
        ...readCaptureSnapshot(payload),
      },
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
        mode={state.mode}
        loading={state.loading}
        snapshot={state.snapshot}
        pendingCount={state.pending.length}
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
          <PanelLine label="Protocol" value={state.snapshot.protocolVersion} />
          <PanelLine label="Methods" value={String(state.snapshot.methodCount)} />
          <PanelLine label="Events" value={String(state.snapshot.eventCount)} />
          <PanelLine label="Interfaces" value={state.snapshot.interfaces.join(", ")} />
          <PanelLine label="RunState" value={state.snapshot.runState} />
          <PanelLine label="Capture" value={state.snapshot.captureStatus} />
          <PanelLine label="CaptureId" value={state.snapshot.captureId} />
          <PanelLine label="Interface" value={state.snapshot.captureInterface} />
          <PanelLine label="Pending" value={String(state.pending.length)} />
          <PanelLine label="Findings" value={String(state.alerts.length)} />

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
            <text fg="#94a3b8">{selectedPrompt}</text>
            <text fg="#64748b">
              Enter send | Tab cycle prompt | c request capture | x stop capture | y/a/n/f reply approval | q quit
            </text>
            <text fg="#e2e8f0">{truncate(state.lastAgentResult, 220)}</text>
          </box>
        </box>
      </box>

      <ApprovalModal request={state.pending[0]} visible={state.pending.length > 0} />
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

function buildSnapshot(
  capabilities: unknown,
  interfaces: unknown,
  capture: unknown,
): DashboardSnapshot {
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
    ...readCaptureSnapshot(capture),
  }
}

function readCaptureSnapshot(payload: unknown): Pick<
  DashboardSnapshot,
  "captureStatus" | "captureId" | "captureInterface"
> {
  const capture = payload as {
    status?: string
    capture_id?: string
    interface?: string
  }

  return {
    captureStatus: capture.status ?? "idle",
    captureId: capture.capture_id ?? "n/a",
    captureInterface: capture.interface ?? "n/a",
  }
}

function readPending(payload: unknown): PendingApproval[] {
  const pending = (payload as { pending?: PendingApproval[] }).pending
  return pending ?? []
}

function reduceEvent(current: UiState, event: CoreEvent): UiState {
  const next = { ...current, events: [...current.events, event] }

  if (event.method === "permission.asked") {
    const request = (event.params as { request?: PendingApproval }).request
    if (!request) return next
    return {
      ...next,
      mode: "approval",
      pending: [...current.pending, request],
    }
  }

  if (event.method === "permission.replied") {
    const requestId = (event.params as { request_id?: string }).request_id
    if (!requestId) return next
    return {
      ...next,
      pending: current.pending.filter((item) => item.id !== requestId),
      mode: current.pending.length > 1 ? "approval" : "dashboard",
    }
  }

  if (event.method === "finding.created") {
    const finding = normalizeFinding(event.params)
    return {
      ...next,
      alerts: [...current.alerts, finding],
    }
  }

  if (event.method === "capture.started") {
    const payload = event.params as {
      capture_id?: string
      interface?: string
    }
    return {
      ...next,
      snapshot: {
        ...next.snapshot,
        captureStatus: "running",
        captureId: payload.capture_id ?? next.snapshot.captureId,
        captureInterface: payload.interface ?? next.snapshot.captureInterface,
      },
    }
  }

  if (event.method === "capture.stopped") {
    return {
      ...next,
      snapshot: {
        ...next.snapshot,
        captureStatus: "stopped",
      },
    }
  }

  return next
}

function normalizeFinding(payload: unknown): AlertItem {
  const finding = payload as {
    id?: string
    severity?: string
    title?: string
    summary?: string
  }

  return {
    id: finding.id ?? `finding-${Date.now()}`,
    severity: finding.severity ?? "low",
    title: finding.title ?? "Unknown finding",
    summary: finding.summary ?? "No summary",
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
