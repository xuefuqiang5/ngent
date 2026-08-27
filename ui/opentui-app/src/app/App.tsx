import { useEffect, useMemo, useRef, useState } from "react"
import type { KeyEvent } from "@opentui/core"
import { decodePasteBytes } from "@opentui/core"
import {
  useKeyboard,
  usePaste,
  useRenderer,
  useTerminalDimensions,
} from "@opentui/react"
import type { CoreEvent } from "../harness/event_router"
import type { RpcClient } from "../harness/rpc_client"
import type { StdioTransport } from "../harness/transport"
import type {
  AlertItem,
  AppState,
  CaptureState,
  ChatMessage,
  DashboardSnapshot,
  PersistedMessage,
  PersistedSessionSnapshot,
  PersistedSessionSummary,
  PersistedToolCall,
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
  const terminal = useTerminalDimensions()
  const [state, setState] = useState<AppState>(initialState())
  const viewMode = deriveViewMode(state)
  const [confirmInput, setConfirmInput] = useState("")
  const [confirmError, setConfirmError] = useState<string | undefined>(undefined)
  const sessionIdRef = useRef<string | undefined>(undefined)
  const resumeInFlightRef = useRef(false)
  sessionIdRef.current = state.session.sessionId

  useEffect(() => {
    let mounted = true

    const unsubscribe = eventRouter.onEvent((event) => {
      if (!mounted) return
      setState((current: AppState) => reduceEvent(current, event))
      if (event.method === "pcap.created" || event.method === "capture.stopped") {
        void tryResumeSession()
      }
    })

    void hydrate()

    return () => {
      mounted = false
      unsubscribe()
      void transport.close()
    }
  }, [eventRouter, rpc, transport])

  async function tryResumeSession(): Promise<void> {
    const sessionId = sessionIdRef.current
    if (!sessionId || resumeInFlightRef.current) return
    resumeInFlightRef.current = true
    try {
      await rpc.request("agent.resume", { session_id: sessionId })
    } catch {
      // No continuation (or capture still running) is expected; the UI stays
      // read-only and retries after the next pcap.created/capture.stopped.
    } finally {
      resumeInFlightRef.current = false
    }
  }

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
      const request = state.permission.pending[0]
      if (request.require_typed_confirmation) {
        if (event.name === "return") {
          const phrase = confirmInput.trim()
          if (phrase.length > 0) void replyToPermission("once", phrase)
          return
        }
        if (event.name === "escape") {
          setConfirmInput("")
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
        setConfirmInput((current) => applyChatInputKey(current, event))
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

  usePaste((event) => {
    const text = sanitizePastedText(decodePasteBytes(event.bytes))
    if (!text) return

    if (state.permission.pending[0]?.require_typed_confirmation) {
      setConfirmInput((current) => current + text)
      return
    }
    if (!canSubmitPrompt(state)) return

    setState((current: AppState) => ({
      ...current,
      session: {
        ...current.session,
        chatInput: current.session.chatInput + text,
      },
    }))
  })

  const density = responsiveDensity(terminal.width, terminal.height)

  const recentMessages = useMemo(
    () => state.session.messages.slice(-density.messageLimit),
    [state.session.messages, density.messageLimit],
  )
  const workTrace = useMemo(
    () =>
      state.events
        .map(summarizeCoreEvent)
        .filter(isTraceItem)
        .filter((item) => item.title !== "Tool progress")
        .slice(-density.traceLimit),
    [state.events, density.traceLimit],
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
      const dashboardSnapshot = buildSnapshot(capabilities, interfaces)

      setState((current: AppState) => ({
        ...current,
        sync: { status: "ready" },
        dashboard: {
          ...dashboardSnapshot,
          runState: dashboardSnapshot.runState,
        },
        capture: readCaptureSnapshot(captureStatus),
        permission: {
          ...current.permission,
          pending: readPending(pending).filter(
            (request) => request.session_id === current.session.sessionId,
          ),
        },
        session: {
          ...current.session,
          sessionId: current.session.sessionId,
          status: "idle",
          messages: markSystemMessage(
            current.session.sessionId === "n/a" ? current.session.messages : [],
            current.session.sessionId === "n/a"
              ? "Core connected. This window will start a new session."
              : "Core state refreshed. Continue this window's session.",
          ),
        },
        events: current.events,
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
          messages: upsertChatMessage(current.session.messages, {
            id: response.assistant_message?.id ?? nextUiId("chat_assistant"),
            role: "assistant",
            status: "sent",
            content: assistantText ?? JSON.stringify(result),
          }),
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
    typedConfirmation?: string,
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
        typed_confirmation:
          typedConfirmation !== undefined ? typedConfirmation : undefined,
      })

      setConfirmInput("")
      setConfirmError(undefined)
      const pending = await rpc.request("permission.list_pending")
      setState((current: AppState) => ({
        ...current,
        permission: {
          pending: readPending(pending),
        },
      }))
      await refreshCaptureStatus()
      await tryResumeSession()
    } catch (error) {
      if (request.require_typed_confirmation) {
        setConfirmError(error instanceof Error ? error.message : String(error))
      }
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
        compact={density.compact}
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
            <ThreadMessage
              key={message.id}
              message={message}
              lineLimit={density.compact ? 6 : 14}
            />
          ))}

          {state.session.streamingText ? (
            <ThreadMessage
              key="chat_streaming"
              message={{
                id: "chat_streaming",
                role: "assistant",
                status: "sent",
                content: state.session.streamingText,
              }}
              lineLimit={density.compact ? 6 : 14}
            />
          ) : null}

          {workTrace.length > 0 ? (
            <box flexDirection="column" marginTop={1} gap={0}>
              {workTrace.map((item, index) => (
                <TraceLine key={`${item.title}-${index}`} item={item} />
              ))}
            </box>
          ) : null}

          <AgentCapabilityStrip snapshot={state.dashboard} />

          <InlinePermissionCard
            request={state.permission.pending[0]}
            confirmInput={confirmInput}
            confirmError={confirmError}
          />

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
  if (event.name === "backspace") return removeLastGrapheme(value)
  if (event.name === "delete") return removeLastGrapheme(value)
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

export function sanitizePastedText(value: string): string {
  return value
    .replace(/\r\n?/g, "\n")
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "")
}

export function removeLastGrapheme(value: string): string {
  if (!value) return value
  const segmenter = new Intl.Segmenter(undefined, { granularity: "grapheme" })
  const segments = Array.from(segmenter.segment(value))
  return segments.slice(0, -1).map((entry) => entry.segment).join("")
}

export function responsiveDensity(width: number, height: number): {
  compact: boolean
  messageLimit: number
  traceLimit: number
} {
  const compact = width < 72 || height < 24
  if (height < 16) return { compact: true, messageLimit: 2, traceLimit: 1 }
  if (compact) return { compact: true, messageLimit: 4, traceLimit: 3 }
  return { compact: false, messageLimit: 8, traceLimit: 8 }
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

export function readLatestSession(payload: unknown): PersistedSessionSummary | undefined {
  const sessions = (payload as { sessions?: unknown }).sessions
  if (!Array.isArray(sessions)) return undefined

  const first = sessions[0] as Partial<PersistedSessionSummary> | undefined
  if (!first || typeof first.id !== "string" || first.id.length === 0) {
    return undefined
  }

  return {
    id: first.id,
    mode: typeof first.mode === "string" ? first.mode : undefined,
    run_state: typeof first.run_state === "string" ? first.run_state : undefined,
    max_steps: typeof first.max_steps === "number" ? first.max_steps : undefined,
  }
}

export function readRestoredChatMessages(payload: unknown): ChatMessage[] {
  const messages = (payload as { messages?: unknown }).messages
  if (!Array.isArray(messages)) return []

  return messages
    .map((item) => normalizePersistedMessage(item))
    .filter((item): item is ChatMessage => item !== null)
}

export function readRestoredToolEvents(payload: unknown): CoreEvent[] {
  const snapshot = payload as PersistedSessionSnapshot | undefined
  const toolCalls = snapshot?.tool_calls
  const goalEvents = readPersistedGoalEvents(snapshot?.messages)
  if (!Array.isArray(toolCalls)) return goalEvents
  const resultSummaries = readPersistedToolResultSummaries(snapshot?.messages)

  return [
    ...goalEvents,
    ...toolCalls
    .map((toolCall) =>
      restoredToolEvent(
        toolCall,
        typeof toolCall.id === "string"
          ? resultSummaries.get(toolCall.id)
          : undefined,
      ),
    )
    .filter((event): event is CoreEvent => event !== null),
  ]
}

function readPersistedGoalEvents(
  messages: PersistedMessage[] | undefined,
): CoreEvent[] {
  if (!Array.isArray(messages)) return []
  const events: CoreEvent[] = []
  for (const message of messages) {
    for (const part of message.parts ?? []) {
      if (part.kind !== "reasoning" || typeof part.content !== "string") continue
      try {
        const goalAnalysis = JSON.parse(part.content) as unknown
        events.push({
          method: "agent.reasoning.ended",
          params: {
            message_id: message.id,
            part_id: part.id,
            goal_analysis: goalAnalysis,
          },
        })
      } catch {
        // Ignore malformed legacy reasoning parts.
      }
    }
  }
  return events
}

function readPersistedToolResultSummaries(
  messages: PersistedMessage[] | undefined,
): Map<string, string> {
  const summaries = new Map<string, string>()
  if (!Array.isArray(messages)) return summaries

  for (const message of messages) {
    for (const part of message.parts ?? []) {
      if (part.kind !== "tool_result" || typeof part.content !== "string") continue
      try {
        const envelope = JSON.parse(part.content) as {
          call_id?: unknown
          result?: { summary?: unknown }
        }
        if (
          typeof envelope.call_id === "string" &&
          typeof envelope.result?.summary === "string"
        ) {
          summaries.set(envelope.call_id, envelope.result.summary)
        }
      } catch {
        // Ignore malformed legacy parts and preserve the tool-call status trace.
      }
    }
  }
  return summaries
}

function mergeRestoredToolEvents(
  restored: CoreEvent[],
  current: CoreEvent[],
): CoreEvent[] {
  const restoredIds = new Set(restored.map(readAgentEventId).filter(Boolean))
  return [
    ...restored,
    ...current.filter((event) => {
      const id = readAgentEventId(event)
      return !id || !restoredIds.has(id)
    }),
  ]
}

function readAgentEventId(event: CoreEvent): string | undefined {
  return readToolCallId(event) ?? getString(event.params, "message_id")
}

function readToolCallId(event: CoreEvent): string | undefined {
  return (
    getString(event.params, "tool_call_id") ??
    getString((event.params as { tool_call?: unknown }).tool_call, "id")
  )
}

function restoredToolEvent(
  toolCall: PersistedToolCall,
  summary?: string,
): CoreEvent | null {
  if (typeof toolCall.tool_name !== "string") return null

  if (toolCall.status === "completed") {
    return {
      method: "agent.tool.success",
      params: { tool_call: toolCall, summary },
    }
  }
  if (toolCall.status === "error" || toolCall.status === "aborted") {
    return {
      method: "agent.tool.failed",
      params: { tool_call: toolCall, summary },
    }
  }
  return { method: "agent.tool.called", params: { tool_call: toolCall } }
}

function restoredSessionStatus(
  session: PersistedSessionSummary | undefined,
): AppState["session"]["status"] {
  if (!session?.run_state) return "idle"
  if (session.run_state === "error" || session.run_state === "retrying") {
    return "retry"
  }
  if (
    [
      "busy",
      "running_tool",
      "capturing",
      "analyzing",
      "reporting",
      "compacting",
      "canceling",
    ].includes(session.run_state)
  ) {
    return "busy"
  }
  return "idle"
}

function normalizePersistedMessage(payload: unknown): ChatMessage | null {
  const message = payload as Partial<PersistedMessage>
  if (typeof message.id !== "string") return null

  const role = normalizeChatRole(message.role)
  if (!role) return null

  const content = (message.parts ?? [])
    .filter((part) => part.kind === "text" && typeof part.content === "string")
    .map((part) => part.content)
    .join("\n")
    .trim()

  if (!content) return null

  return {
    id: message.id,
    role,
    status: "sent",
    content,
  }
}

function normalizeChatRole(role: unknown): ChatMessage["role"] | null {
  if (role === "user" || role === "assistant") return role
  if (role === "tool") return "system"
  return null
}

function ThreadMessage(props: {
  message: AppState["session"]["messages"][number]
  lineLimit?: number
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
      <text fg="#e2e8f0">
        {formatTuiModelText(props.message.content, props.lineLimit ?? 14)}
      </text>
    </box>
  )
}

function AgentCapabilityStrip(props: { snapshot: DashboardSnapshot }) {
  const model = props.snapshot.llmEnabled
    ? props.snapshot.llmModel
    : "deterministic local planner"
  const tools =
    props.snapshot.agentTools.length > 0
      ? props.snapshot.agentTools.join(" · ")
      : "no agent tools advertised"
  return (
    <box flexDirection="column" marginTop={1}>
      <text fg="#64748b">{`Agent: ${model}`}</text>
      <text fg="#64748b">{`Tools: ${truncate(tools, 180)}`}</text>
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

function InlinePermissionCard(props: {
  request?: PendingApproval
  confirmInput?: string
  confirmError?: string
}) {
  const request = props.request
  if (!request) return null

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
        {`permission required · ${request.risk} risk${request.require_typed_confirmation ? " · typed confirmation" : ""}`}
      </text>
      <text fg="#e5e7eb">{request.metadata.tool}</text>
      <text fg="#cbd5e1">{truncate(request.metadata.reason, 180)}</text>
      {request.patterns.length > 0 ? (
        <text fg="#94a3b8">
          {`scope: ${truncate(request.patterns.join(" "), 160)}`}
        </text>
      ) : null}
      <text fg="#94a3b8">
        {`preview: ${truncate(request.metadata.command_preview, 180)}`}
      </text>
      {request.require_typed_confirmation ? (
        <box flexDirection="column" gap={1}>
          <text fg="#f97316">
            {`type confirmation phrase: ${request.metadata.confirm_phrase ?? "(not configured)"}`}
          </text>
          <text fg="#f8fafc">
            {`> ${props.confirmInput ?? ""}${props.confirmInput?.length ? "▌" : ""}`}
          </text>
          {props.confirmError ? (
            <text fg="#f87171">{`confirmation rejected: ${truncate(props.confirmError, 140)}`}</text>
          ) : null}
          <text fg="#d97706">
            [Enter] approve (once)   [N] reject   [F] feedback   [Esc] clear
          </text>
        </box>
      ) : (
        <text fg="#d97706">[Y] once   [A] always   [N] reject   [F] feedback</text>
      )}
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
  if (event.method === "agent.reasoning.started") {
    return {
      title: "Analyzing goal",
      detail: "building a bounded execution plan",
      status: "running",
    }
  }

  if (event.method === "agent.reasoning.ended") {
    const analysis = (event.params as { goal_analysis?: unknown }).goal_analysis
    const objective = getString(analysis, "objective") ?? "goal analyzed"
    const selectedTools = (analysis as { selected_tools?: unknown })?.selected_tools
    const toolSummary = Array.isArray(selectedTools)
      ? selectedTools.filter((tool): tool is string => typeof tool === "string").join(", ")
      : ""
    return {
      title: "Goal analyzed",
      detail: truncate(
        toolSummary ? `${objective} · plan: ${toolSummary}` : objective,
        180,
      ),
      status: "done",
    }
  }

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
    const summary = getString(event.params, "summary")
    return {
      title: "Tool completed",
      detail: summary
        ? `${readToolName(event.params)} · ${truncate(summary, 140)}`
        : readToolName(event.params),
      status: "done",
    }
  }

  if (event.method === "agent.tool.failed") {
    const detail =
      getString(event.params, "summary") ??
      getString(event.params, "message") ??
      readToolName(event.params)
    return {
      title: "Tool did not complete",
      detail: truncate(detail, 140),
      status: "error",
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
    agent_tools?: Array<{ id?: string }>
    llm?: { enabled?: boolean; model?: string }
  }
  const network = interfaces as { interfaces?: Array<{ name?: string }> }

  return {
    protocolVersion: caps.protocol_version ?? "2.0",
    methodCount: caps.methods?.length ?? 0,
    eventCount: caps.events?.length ?? 0,
    interfaces: (network.interfaces ?? []).map((item) => item.name ?? "unknown"),
    runState: caps.phase ?? "unknown",
    agentTools: (caps.agent_tools ?? [])
      .map((tool) => tool.id)
      .filter((id): id is string => typeof id === "string"),
    llmEnabled: caps.llm?.enabled ?? false,
    llmModel: caps.llm?.model ?? "local planner",
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

  if (event.method === "agent.text.started") {
    return {
      ...next,
      session: {
        ...current.session,
        streamingText: "",
      },
    }
  }

  if (event.method === "agent.text.delta") {
    const delta = getString(event.params, "delta") ?? ""
    if (!delta) return next
    return {
      ...next,
      session: {
        ...current.session,
        streamingText: truncate(
          (current.session.streamingText ?? "") + sanitizeDisplayText(delta),
          6_000,
        ),
      },
    }
  }

  if (event.method === "agent.text.ended") {
    return {
      ...next,
      session: {
        ...current.session,
        streamingText: undefined,
      },
    }
  }

  if (event.method === "message.created") {
    const message = (event.params as { message?: unknown }).message as
      | {
          id?: string
          role?: string
          parts?: Array<{ kind?: string; content?: string }>
        }
      | undefined
    if (message?.role === "assistant") {
      const text = (message.parts ?? [])
        .filter((part) => part.kind === "text")
        .map((part) => part.content ?? "")
        .join("\n")
      if (!text) return next
      return {
        ...next,
        session: {
          ...current.session,
          streamingText: undefined,
          messages: upsertChatMessage(current.session.messages, {
            id: message.id ?? nextUiId("chat_assistant"),
            role: "assistant" as const,
            status: "sent" as const,
            content: text,
          }),
        },
      }
    }
    return next
  }

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

export function upsertChatMessage(
  messages: ChatMessage[],
  message: ChatMessage,
): ChatMessage[] {
  const index = messages.findIndex((candidate) => candidate.id === message.id)
  if (index < 0) return [...messages, message]
  const next = [...messages]
  next[index] = message
  return next
}

export function sanitizeDisplayText(value: string): string {
  return value
    .replace(/\r\n?/g, "\n")
    .replace(/\t/g, "  ")
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g, "")
}

export function formatTuiModelText(value: string, maxLines = 14): string {
  const source = sanitizeDisplayText(value)
  const lines: string[] = []
  let inFence = false

  for (const rawLine of source.split("\n")) {
    const trimmed = rawLine.trim()
    if (/^```/.test(trimmed)) {
      inFence = !inFence
      continue
    }
    if (/^\|?(?:\s*:?-{3,}:?\s*\|)+\s*$/.test(trimmed)) continue

    let line = rawLine
      .replace(/^\s{0,3}#{1,6}\s+/, "")
      .replace(/^\s*>\s?/, "")
      .replace(/^\s*[-*+]\s+/, "• ")
      .replace(/^\s*(\d+)\.\s+/, "$1. ")
    line = stripInlineMarkdown(line)

    if (trimmed.startsWith("|") && trimmed.endsWith("|")) {
      line = trimmed
        .slice(1, -1)
        .split("|")
        .map((cell) => stripInlineMarkdown(cell.trim()))
        .join(" · ")
    } else if (inFence && line.length > 0) {
      line = `  ${line}`
    }
    lines.push(line.replace(/[ \t]+$/g, ""))
  }

  const compacted = lines.filter(
    (line, index) => line.length > 0 || lines[index - 1]?.length !== 0,
  )
  if (compacted.length <= maxLines) return compacted.join("\n")
  return `${compacted.slice(0, maxLines).join("\n")}\n… output shortened for this view`
}

function stripInlineMarkdown(value: string): string {
  return value
    .replace(/!\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, "$1 ($2)")
    .replace(/(\*\*|__)(.*?)\1/g, "$2")
    .replace(/(?<!\*)\*([^*\n]+)\*(?!\*)/g, "$1")
    .replace(/(?<!_)_([^_\n]+)_(?!_)/g, "$1")
    .replace(/~~(.*?)~~/g, "$1")
    .replace(/`([^`]+)`/g, "$1")
}
