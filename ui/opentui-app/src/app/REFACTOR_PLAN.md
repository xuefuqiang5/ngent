# State Architecture Refactor Plan

> **Current project phase:** Phase 9 partial — User-Assistant Interaction Maturity (per `netagent_build_spec.md`)
> **Implementation status:** P0 and P1 are implemented. P2 capture tool modeling is deferred to Phase 12.
> **Anti-drift compliance:** This refactor addresses the rule *"Do not let UI or harness execute system commands directly."*

---

## Status Summary

- P0 correctness fixes are complete.
- P1 state architecture refactor is complete.
- `viewMode` is derived via `deriveViewMode(state)` and must not be manually written.
- Prompt submission is gated by `canSubmitPrompt(state)`.
- `Ctrl+X` no longer calls `capture.stop`; do not reintroduce direct UI capture-control shortcuts.
- P2 capture tool modeling requires backend LLM tool-calling infrastructure and must wait until Phase 12.

---

## Problem Statement

Before this refactor, `state.ts` used a single `mode: UiMode` field (`"dashboard" | "agent" | "approval" | "syncing"`) to represent four unrelated concerns:

| Concern                                 | Where it leaks into `mode`               |
| --------------------------------------- | ---------------------------------------- |
| Backend sync lifecycle                  | `syncing` is a transient I/O phase       |
| Agent conversation liveness             | `agent` conflates "chat panel" and "agent running" |
| Permission interrupt / block            | `approval` is an overlay, not a view mode |
| Idle monitoring                         | `dashboard` is the default resting state |

This caused three concrete problems verified against the old code:

1. **Deterministic bug** — Enter key bypasses approval (L90 in `App.tsx` has no mode gate; `sendAgentPrompt` L150 only checks `state.loading`).
2. **Anti-drift violation** — `Ctrl+X` calls `capture.stop` RPC directly (L60-63), bypassing the Agent → Permission → Tool execution chain.
3. **Hydrate failure lands on `agent`** — `syncing → agent` on catch (L130-134) implies the system is ready for conversation when capabilities may not have loaded.

---

## Target Architecture

### Before (current)

```
UiState {
  mode           ← manually written in 7 locations
  loading        ← 4 different meanings
  snapshot       ← flat dashboard data
  chatMessages   ← interleaved with mode logic
  pending        ← array but mode duplicates its signal
  alerts / events / lastPrompt / lastAgentResult
}
```

### After (target)

```
AppState {
  sync       → status: "syncing" | "ready" | "error"
  session    → status: "idle" | "busy" | "retry"
               chatInput, messages
  permission → pending: PermissionRequest[]
               replying?: string
  capture    → status, interfaces (read-only observation)
}

viewMode is derived, never written:
  sync.status === "syncing"          → "syncing"
  permission.pending.length > 0      → "approval"
  session.status === "busy"          → "agent"
  else                               → "dashboard"
```

---

## Comparison Table

| Dimension                  | Before (current code)                              | After (target)                                       |
| -------------------------- | -------------------------------------------------- | ---------------------------------------------------- |
| **State modeling**         | 1 monolithic `UiState`                             | 4 independent slices: `sync`, `session`, `permission`, `capture` |
| **mode origin**            | Manually written via `setState` in 7 call sites    | `viewMode` is a derived getter, read-only            |
| **loading semantics**      | 1 `boolean` for 4 meanings (sync, agent RPC, stop-capture, reply-permission) | `sync.status` (syncing\|ready\|error) + `session.status` (idle\|busy\|retry) |
| **Enter key under approval** | ❌ Bypasses approval gate; sends new prompt        | ✅ Hard-blocked by `canSubmitPrompt` selector        |
| **Ctrl+X stop-capture**    | Direct `rpc.request("capture.stop")` in keyboard handler | Removed as shortcut; modeled as agent tool `capture_stop` going through permission |
| **Hydrate failure**        | `mode → "agent"` (implies ready for conversation)  | `sync.status → "error"`; prompt submission disabled  |
| **dashboard vs agent**     | Two mutually exclusive modes rendering identical layout | Merged; `session.status` differentiates idle vs busy |
| **Permission modeling**    | Array `pending[]` exists, but `mode` duplicates its signal | `pending[]` is the sole source of truth; modal visibility driven by `pending.length > 0` |
| **Capture polling**        | `setInterval` in `useEffect`, unconditionally runs | Independent `useCaptureStatusPolling(enabled: sync.ready)` |
| **Keyboard handler**       | Linear if-else on `pending.length > 0`             | Layered guard: exit → refresh → approval → submit → input |
| **State mutation surface** | 7 locations write `mode` directly                  | `mode` no longer written; only underlying slice fields are mutated |
| **Testability**            | One giant state object                             | Each slice independently testable                    |
| **Cost of adding a state** | Insert condition into every if-else branch         | Modify `deriveViewMode()` only                       |

---

## Implementation Steps

### Phase 0 — P0: Fix correctness bugs (DONE)

#### Step 0.1 — Guard Enter key against approval and sync states

**File:** `ui/opentui-app/src/app/App.tsx`

Add a `canSubmitPrompt` guard before calling `sendAgentPrompt`:

```ts
function canSubmit(state: UiState): boolean {
  if (state.mode === "syncing") return false
  if (state.mode === "approval") return false
  if (state.loading) return false
  return true
}
```

Change keyboard handler L90:
```diff
- if (event.name === "return") {
-   void sendAgentPrompt()
-   return
- }
+ if (event.name === "return") {
+   if (canSubmit(state)) void sendAgentPrompt()
+   return
+ }
```

Also add the same guard inside `sendAgentPrompt` (defense in depth):
```diff
- if (!prompt || state.loading) return
+ if (!prompt || state.loading) return
+ if (state.mode === "syncing" || state.mode === "approval") return
```

#### Step 0.2 — Remove Ctrl+X as a direct capture RPC shortcut

**File:** `ui/opentui-app/src/app/App.tsx`

```diff
- if (event.ctrl && event.name === "x") {
-   void stopCapture()
-   return
- }
```

Remove the `stopCapture` function (L216-221) or repurpose it as a prompt shortcut:

```ts
// Option A: remove entirely
// Option B: convert to a prompt that asks agent to stop capture
async function requestStopCapture(): Promise<void> {
  setState(c => ({ ...c, chatInput: "stop capture" }))
  await sendAgentPrompt()
}
```

Capture control should only flow through: User prompt → Agent decision → tool invocation → permission gate → execution.

---

### Phase 1 — P1: Architectural improvements (DONE)

#### Step 1.1 — Split UiState into slices

**File:** `ui/opentui-app/src/app/state.ts`

```ts
// ── Sync Slice ──
export type SyncStatus = "syncing" | "ready" | "error"
export type SyncState = {
  status: SyncStatus
  error?: string
}

// ── Session Slice ──
export type SessionStatus = "idle" | "busy" | "retry"
export type ChatMessage = {
  id: string
  role: "user" | "assistant" | "system"
  status: "sending" | "sent" | "error"
  content: string
}
export type SessionState = {
  status: SessionStatus
  sessionId: string
  chatInput: string
  messages: ChatMessage[]
  lastPrompt: string
  lastAgentResult: string
}

// ── Permission Slice ──
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
export type PermissionState = {
  pending: PendingApproval[]
  replying?: string
}

// ── Capture Slice (read-only observation) ──
export type CaptureState = {
  status: string
  captureId: string
  captureInterface: string
}

// ── Dashboard Slice ──
export type DashboardSnapshot = {
  protocolVersion: string
  methodCount: number
  eventCount: number
  interfaces: string[]
  runState: string
}

// ── Alert Slice ──
export type AlertItem = {
  id: string
  severity: string
  title: string
  summary: string
}

// ── Aggregated App State ──
export type AppState = {
  sync: SyncState
  session: SessionState
  permission: PermissionState
  capture: CaptureState
  dashboard: DashboardSnapshot
  alerts: AlertItem[]
  events: Array<{ method: string; params: unknown }>
}
```

#### Step 1.2 — Derive viewMode as a selector

```ts
export type ViewMode = "syncing" | "dashboard" | "agent" | "approval"

export function deriveViewMode(state: AppState): ViewMode {
  if (state.sync.status === "syncing") return "syncing"
  if (state.sync.status === "error") return "syncing" // blocked UI
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
```

#### Step 1.3 — Hydrate failure lands on sync.error, not agent

```ts
// hydrate() error path
catch (error) {
  setState(current => ({
    ...current,
    sync: { status: "error", error: String(error) },
  }))
  // session.status remains "idle", no new messages added as agent
}
```

#### Step 1.4 — Extract capture polling as independent effect

```ts
function useCapturePolling(enabled: boolean) {
  useEffect(() => {
    if (!enabled) return
    const interval = setInterval(() => refreshCaptureStatus(), 1000)
    return () => clearInterval(interval)
  }, [enabled])
}
```

#### Step 1.5 — Restructure keyboard handler

```ts
useKeyboard((event) => {
  if (event.eventType === "release") return

  // Layer 1 — Global exit
  if (event.name === "escape" || (event.ctrl && event.name === "c")) {
    renderer.destroy()
    return
  }

  // Layer 2 — Global refresh
  if (event.ctrl && event.name === "r") {
    void hydrate()
    return
  }

  // Layer 3 — Permission keys (if pending)
  if (state.permission.pending.length > 0) {
    if (event.name === "y") { void replyToPermission("once"); return }
    if (event.name === "a") { void replyToPermission("always"); return }
    if (event.name === "n") { void replyToPermission("reject"); return }
    if (event.name === "f") { void replyToPermission("reject_with_feedback"); return }
    return // block all other keys when approval is active
  }

  // Layer 4 — Submit prompt
  if (event.name === "return") {
    if (canSubmitPrompt(state)) void sendAgentPrompt()
    return
  }

  // Layer 5 — Text input
  setState(current => ({
    ...current,
    session: { ...current.session, chatInput: applyChatInputKey(current.session.chatInput, event) },
  }))
})
```

---

### Phase 2 — P2: Capture tool modeling (DEFERRED TO PHASE 12)

> **Note:** This requires corresponding backend tool registration and LLM tool-calling infrastructure. Do not implement before Phase 10 session persistence and Phase 11 read-only tool-calling are complete.

Register capture operations as agent tools:

```
Tool: capture_start
  Description: "Start packet capture on a network interface"
  Permission: "capture.start"
  Parameters: { interface: string, filter?: string }

Tool: capture_stop
  Description: "Stop the active packet capture"
  Permission: "capture.stop"
  Parameters: {}

Tool: capture_status
  Description: "Get current capture status"
  Permission: "capture.read"
  Parameters: {}
```

Capture status polling remains as read-only observation, not a control path.

#### Step 2.1 — Delegate capture execution to a sub-agent, not the main agent

> **⚠️ Aspirational — do not implement now.** This section is a forward-looking
> design note. Sub-agent delegation requires backend infrastructure that does not
> exist in the current phase. Keep this as a reference for future architecture
> decisions; no code changes should be made based on this section at this time.

Capture operations (e.g., `tcpdump`) are long-running by nature. If the main agent
blocks on a capture tool invocation, the conversation stalls — the user cannot send
follow-up prompts, ask clarifying questions, or approve other pending permissions
until the capture completes.

**Recommendation:** model capture tools as **sub-agent tasks** that run in parallel
with the main conversation loop.

```
User: "capture traffic on eth0 for 60 seconds"
  │
  ▼
Main Agent: decides to start capture
  │
  ├─→ Spawns Capture Sub-Agent (runs independently)
  │     └─→ capture_start on eth0
  │     └─→ collect packets (60s)
  │     └─→ capture_stop
  │     └─→ return results to Main Agent
  │
  ▼
Main Agent: continues conversation immediately
  "Capture started on eth0. I'll notify you when it completes."
  User can now ask other questions while capture runs.
```

This avoids the blocking problem:

| Approach                          | Capture runs | User can chat | Risk                           |
| --------------------------------- | ------------ | ------------- | ------------------------------ |
| Main agent calls capture directly | yes          | ❌ blocked    | Session appears frozen for 60s |
| Sub-agent runs capture            | yes          | ✅ parallel   | Main agent stays responsive    |

The sub-agent reports results back via the event stream (`capture.completed` or
`agent.result`), and the main agent incorporates them into its next response.

**Implementation notes:**
- The sub-agent shares the same tool registry and permission state machine as the main agent.
- Capture tools should still go through the permission gate (`permission.asked`) before execution, even when invoked by a sub-agent.
- The UI does not need to know whether a tool is executed by the main agent or a sub-agent — it only sees events and renders results.

---

## Keyboard Behavior Matrix (Target)

| Key               | syncing | dashboard | agent (busy) | agent (idle) | approval |
| ----------------- | ------- | --------- | ------------ | ------------ | -------- |
| `Escape / Ctrl+C` | quit    | quit      | quit         | quit         | quit     |
| `Ctrl+R`          | re-sync | re-sync   | re-sync      | re-sync      | re-sync  |
| `Ctrl+X`          | —       | —         | —            | —            | —        |
| `Y / A / N / F`   | —       | —         | —            | —            | approve  |
| `Enter`           | blocked | submit    | blocked      | submit       | blocked  |
| `Backspace`       | type    | type      | type         | type         | blocked  |
| All other chars   | type    | type      | type         | type         | blocked  |

---

## Verification Checklist

After each step:

- [ ] `bun test` passes for `App.test.ts`
- [ ] Manual smoke: launch app, verify StatusBar shows correct mode
- [ ] Send a prompt that triggers permission → approval overlay appears → press Enter → **no new prompt sent**
- [ ] `Ctrl+X` no longer stops capture
- [ ] `Ctrl+R` during `syncing` re-initiates hydration
- [ ] Hydrate failure displays error, does not allow prompt submission
- [ ] Anti-drift rules from `AGENTS.md` are not violated

---

## Files Affected

| File                                          | Change scope           |
| --------------------------------------------- | ---------------------- |
| `ui/opentui-app/src/app/state.ts`             | Rewrite type definitions and initial state |
| `ui/opentui-app/src/app/App.tsx`              | Refactor keyboard handler, remove Ctrl+X, add guards |
| `ui/opentui-app/src/components/status_bar.tsx` | Update props to new state shape |
| `ui/opentui-app/src/components/approval_modal.tsx` | May update props |
| `ui/opentui-app/src/app/App.test.ts`          | Update tests to match new state shape |
