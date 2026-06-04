export function describeWorkspace(): string {
  return "NetAgent minimal OpenTUI workspace is connected to the Rust Core."
}

export type UiMode = "dashboard" | "agent" | "approval" | "syncing"

export type DashboardSnapshot = {
  protocolVersion: string
  methodCount: number
  eventCount: number
  interfaces: string[]
  runState: string
  captureStatus: string
  captureId: string
  captureInterface: string
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

export type UiState = {
  mode: UiMode
  loading: boolean
  selectedPromptIndex: number
  snapshot: DashboardSnapshot
  sessionId: string
  chatInput: string
  chatMessages: ChatMessage[]
  pending: PendingApproval[]
  alerts: AlertItem[]
  events: Array<{ method: string; params: unknown }>
  lastPrompt: string
  lastAgentResult: string
}

export function initialState(): UiState {
  return {
    mode: "syncing",
    loading: true,
    selectedPromptIndex: 0,
    snapshot: {
      protocolVersion: "2.0",
      methodCount: 0,
      eventCount: 0,
      interfaces: [],
      runState: "booting",
      captureStatus: "idle",
      captureId: "n/a",
      captureInterface: "n/a",
    },
    sessionId: "n/a",
    chatInput: "",
    chatMessages: [
      {
        id: "chat_system_0001",
        role: "system",
        status: "sent",
        content: "Core is starting. Type a question and press Enter.",
      },
    ],
    pending: [],
    alerts: [],
    events: [],
    lastPrompt: "",
    lastAgentResult: "No agent run yet.",
  }
}
