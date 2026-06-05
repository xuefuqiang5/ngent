export function describeWorkspace(): string {
  return "NetAgent minimal OpenTUI workspace is connected to the Rust Core."
}

export type ViewMode = "dashboard" | "agent" | "approval" | "syncing"

export type SyncStatus = "syncing" | "ready" | "error"

export type SyncState = {
  status: SyncStatus
  error?: string
}

export type DashboardSnapshot = {
  protocolVersion: string
  methodCount: number
  eventCount: number
  interfaces: string[]
  runState: string
}

export type PendingApproval = {
  id: string
  session_id: string
  permission: string
  risk: string
  patterns: string[]
  metadata: {
    tool: string
    command_preview: string
    reason: string
  }
}

export type AlertItem = {
  id: string
  severity: string
  title: string
  summary: string
}

export type ChatMessage = {
  id: string
  role: "user" | "assistant" | "system"
  status: "sending" | "sent" | "error"
  content: string
}

export type SessionStatus = "idle" | "busy" | "retry"

export type SessionState = {
  status: SessionStatus
  sessionId: string
  chatInput: string
  messages: ChatMessage[]
  lastPrompt: string
  lastAgentResult: string
}

export type PermissionState = {
  pending: PendingApproval[]
  replying?: string
}

export type CaptureState = {
  status: string
  captureId: string
  captureInterface: string
}

export type AppState = {
  sync: SyncState
  session: SessionState
  permission: PermissionState
  capture: CaptureState
  dashboard: DashboardSnapshot
  alerts: AlertItem[]
  events: Array<{ method: string; params: unknown }>
}

export type UiState = AppState

export function deriveViewMode(state: AppState): ViewMode {
  if (state.sync.status === "syncing") return "syncing"
  if (state.sync.status === "error") return "syncing"
  if (state.permission.pending.length > 0) return "approval"
  if (state.session.status === "busy") return "agent"
  return "dashboard"
}

export function canSubmitPrompt(state: AppState): boolean {
  return (
    state.sync.status === "ready" &&
    state.session.status !== "busy" &&
    state.permission.pending.length === 0
  )
}

export function initialState(): AppState {
  return {
    sync: {
      status: "syncing",
    },
    session: {
      status: "idle",
      sessionId: "n/a",
      chatInput: "",
      messages: [
        {
          id: "chat_system_0001",
          role: "system",
          status: "sent",
          content: "Core is starting. Type a question and press Enter.",
        },
      ],
      lastPrompt: "",
      lastAgentResult: "No agent run yet.",
    },
    permission: {
      pending: [],
    },
    capture: {
      status: "idle",
      captureId: "n/a",
      captureInterface: "n/a",
    },
    dashboard: {
      protocolVersion: "2.0",
      methodCount: 0,
      eventCount: 0,
      interfaces: [],
      runState: "booting",
    },
    alerts: [],
    events: [],
  }
}
