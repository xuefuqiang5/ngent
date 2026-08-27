# NetAgent OpenTUI UI Design

> Current project phase: Phase 11 complete — LLM Tool-Calling Foundation.
> Scope: the implemented conversation-first UI, persisted session recovery, bounded read-only tool traces, approval flow, and resize robustness.
> Out of scope until later gates: direct UI capture controls, Zeek/Suricata, external intelligence, and firewall actions. Agent-controlled `capture.start` remains the Phase 12 gate.

## Design Goal

NetAgent should feel closer to Claude Code than to a network dashboard. The primary task is not browsing system metrics; it is asking the agent a question, seeing its reasoning/output, reviewing permission requests, and approving or rejecting risky actions.

The UI should therefore make the agent conversation the visual center. Dashboard, activity, capture status, and findings are supporting context. They should be visible when useful, but they must not compete with the conversation thread.

## Product Principles

- Agent-first: the largest and most stable area is the conversation.
- Permission-safe: approval UI is explicit and blocks unrelated input, but it does not become a separate app mode users must mentally switch into.
- Quiet by default: raw JSON events, method counts, protocol version, and capture IDs are debug context, not primary product content.
- Evidence-aware: findings, artifacts, and capture state appear as concise summaries with drill-down potential later.
- Resize-resilient: every layout has a narrow-screen fallback. The input composer must remain visible.
- No direct capture control: UI may show capture state, but must not expose direct `capture.start` or `capture.stop` shortcuts/buttons.

## Business Composition

The UI should be designed around NetAgent's business objects, not around implementation details such as JSON-RPC methods or raw events.

Primary business objects:

- Conversation: user asks, assistant responds, and the investigation advances.
- Agent process: the assistant explains what it is doing at a product level.
- Tool call: Core/Agent performs a typed operation with status and bounded output.
- Permission request: a risky or privileged action awaits explicit user approval.
- Evidence: a traceable artifact, flow, DNS event, finding, report, or IOC output.
- Network context: current interface, capture status, run state, and relevant environment.
- Debug activity: low-level Core events useful for development or troubleshooting.

Business flow:

```text
user prompt
  -> agent explains plan / current understanding
  -> optional tool proposal or tool call
  -> optional permission request
  -> bounded result / evidence summary
  -> assistant answer / next suggested action
```

The UI should make this flow visible as a thread. Users should understand what the model is trying to do, what tool work is happening, and where permission is required.

## UI Display Contract

### Show Prominently

These items belong in the main thread or immediately next to it:

- User messages.
- Assistant answers.
- Agent plan summaries and progress summaries.
- Tool call cards with status: `pending`, `running`, `completed`, `error`, `aborted`.
- Permission cards with risk, reason, preview, and allowed decisions.
- Final evidence summaries and findings that directly answer the user's question.
- Composer blocked reason when input cannot be submitted.

### Show Quietly

These items can appear in the status bar, context rail, or findings strip:

- Core readiness.
- Session status.
- Capture status.
- Interface summary.
- Pending permission count.
- Latest finding severity count.
- Artifact count or latest artifact title.

### Hide Or Collapse By Default

These items should not be visible in the primary experience:

- Raw JSON-RPC event payloads.
- Protocol version, method count, and event count.
- Long session IDs and capture IDs.
- Raw `tcpdump`, `tshark`, Zeek, Suricata, stdout, or stderr output.
- High-frequency packet/flow events.
- Full tool inputs or outputs unless they are short, safe, and user-relevant.

### Never Show As Product Content

- Raw hidden model chain-of-thought.
- Unbounded command output.
- Raw packet streams.
- Shell commands invented by the model.
- Permission/risk decisions made by the UI.

The product should show concise reasoning summaries, plans, observations, uncertainty, evidence references, and next actions. It should not expose private model reasoning text as if it were UI content.

## Required Components

### App Shell

Owns the top-level terminal layout, responsive breakpoint, and global keyboard routing.

Responsibilities:
- Render status, main content, composer, and optional overlays.
- Select a layout variant from terminal width/height.
- Preserve current state invariants: `deriveViewMode(state)` and `canSubmitPrompt(state)`.
- Keep `Esc/Ctrl+C`, `Ctrl+R`, approval keys, Enter, and text input behavior layered.

Non-responsibilities:
- No permission risk decisions.
- No command execution.
- No direct capture control.

### Compact Status Bar

One-line operational summary.

Recommended fields:
- App/Core readiness: `ready`, `syncing`, or `error`
- Session state: `idle`, `busy`, or `retry`
- Capture state: `idle`, `running`, `stopped`
- Interface summary: first interface or `n/a`
- Pending permission count

Avoid by default:
- protocol version
- method count
- event count
- full capture ID
- long session ID

Example:

```text
NetAgent  ready  session:idle  capture:idle  iface:en0  pending:0
```

### Agent Thread

The primary screen surface.

Responsibilities:
- Render recent user and assistant messages.
- Render inline system notices.
- Render inline permission cards.
- Render concise tool/proposal summaries when available.
- Render agent process summaries, tool call cards, and evidence summaries in chronological order.
- Keep the newest content near the composer.

Presentation rule:
- Do not render chat-style `you:` or `agent:` labels.
- User prompts appear as command-style prompt blocks beginning with `>`.
- Assistant output appears as direct text.
- Agent process appears as subdued work-trace sections such as `Plan`, `Checking`, `Reading`, `Summarizing`.
- Tool calls appear as indented dynamic status lines under the relevant process section.
- System/error notices are visually quiet unless they block progress.

Thread item types:

- `UserPrompt`: the user's prompt, rendered as `> ...`.
- `AssistantOutput`: the assistant's user-facing answer, rendered without an `agent:` label.
- `AgentPlan`: a concise summary of what the assistant intends to check.
- `AgentProgress`: a short status update such as "Checking current capture status".
- `ToolCallCard`: typed tool name, status, safe input summary, progress, and result summary.
- `PermissionCard`: risk-marked approval request.
- `EvidenceSummary`: finding/artifact/report references relevant to the answer.
- `SystemNotice`: sync errors, fallback mode, or environment constraints.

Agent process display should be transparent but bounded. Prefer:

```text
Plan
I will first check existing findings and capture status. If current evidence is insufficient, I will ask permission before live capture.
```

Avoid:

```text
raw hidden reasoning transcript
```

### Tool Call Card

Shows typed tool execution without turning the UI into a log stream. The default form should be compact and indented, closer to Claude Code's work trace than to a dashboard card.

Required fields:
- tool name
- lifecycle status
- safe parameter summary
- progress summary, if running
- result summary
- artifact/evidence refs, if produced
- error summary, if failed

Example:

```text
Checking current context
  capture.status
  done: idle
```

Future examples after Phase 11/12:

```text
Reading recent flows
  flow.list
  running...
```

```text
Extracting DNS evidence
  tshark.extract_dns
  done: 184 DNS events extracted
  artifact: artifact_dns_001
```

Rules:
- Do not show unbounded stdout/stderr.
- Do not show raw `tshark -T json`.
- Do not show raw packet streams.
- Show artifacts and evidence refs instead of raw large outputs.

### Composer

The fixed bottom input area.

Responsibilities:
- Always visible unless terminal is below the minimum supported height.
- Shows prompt placeholder.
- Shows blocked reason when Enter is disabled.
- Reflects `canSubmitPrompt(state)`.

Examples:

```text
> Ask NetAgent...
```

Blocked states:
- `syncing`: "Core is syncing"
- `sync.error`: "Core unavailable; Ctrl+R to retry"
- `session.busy`: "Agent is responding"
- `permission.pending`: "Permission required; choose Y/A/N/F"

### Inline Permission Card

Primary approval interaction, rendered close to the related agent message.

Required fields:
- permission kind
- risk
- reason
- command preview, if Core provides it
- allowed decisions: once, always, reject, reject with feedback
- affected scope: interface/filter/duration/artifact when available
- relation to tool call: tool name and call/session id when available

Example:

```text
permission required · medium risk · live capture
tool: capture.start
reason: Capture DNS traffic on en0 for 30 seconds.
scope: iface=en0 filter=dns duration=30s
preview: sudo tcpdump -i en0 -nn -w ...

[Y] once   [A] always   [N] reject   [F] reject with feedback
```

The current absolute modal can remain as an implementation fallback, but the target UX should be inline or near-thread rather than a detached top-right panel.

Visual rules:
- Permission card should be the most visually prominent non-message element.
- Risk label must be visible in the first line.
- The user must be able to approve/reject without scanning a side panel.
- While a permission is pending, the composer should show a blocked reason.

### Findings Strip

Concise security signal summary.

Responsibilities:
- Show only high-value finding summaries.
- Avoid becoming a full alert dashboard.
- Defer detailed evidence views to later phases.

Example:

```text
Findings: 1 high · 2 medium     latest: NXDOMAIN spike from 192.168.1.24
```

### Activity Drawer

Debug/supporting event stream.

Responsibilities:
- Hidden or collapsed by default.
- Shows recent routed Core events when opened.
- Shows event summaries, not raw large JSON.

Target:
- Wide screens may show a narrow debug rail.
- Narrow screens should hide it.

### Context Rail

Optional right-side summary on wide screens only.

Possible sections:
- Network context: run state, interface, capture status.
- Findings summary.
- Recent artifacts.
- Debug activity toggle.

This rail is supportive. It must never be larger or visually stronger than the agent thread.

## Layout Candidates

### Layout A — Claude-Style Single Thread

Recommended starting point.

Best for:
- Agent-first experience.
- Narrow and medium terminal sizes.
- Keeping implementation simple.

Wide screen:

```text
┌ NetAgent  ready  session:idle  capture:idle  iface:en0  pending:0 ┐
│                                                                    │
│  > 最近一小时谁在用网络？                                           │
│                                                                    │
│  我会先查看已有流量摘要。如果需要新的 live evidence，我会说明范围... │
│                                                                    │
│  Checking current context                                           │
│    capture.status                                                  │
│    done: idle                                                      │
│                                                                    │
│  Reading findings                                                  │
│    finding.list                                                    │
│    done: 0 findings                                                │
│                                                                    │
│  permission required · medium risk                                 │
│  capture.start · DNS traffic on en0 for 30 seconds                 │
│  [Y] once   [A] always   [N] reject   [F] feedback                 │
│                                                                    │
│  Findings: none                                                    │
│                                                                    │
├────────────────────────────────────────────────────────────────────┤
│ > Ask NetAgent...                                                  │
└────────────────────────────────────────────────────────────────────┘
```

Narrow screen:

```text
NetAgent ready · idle · pending:0

> 最近一小时谁在用网络？

我会先查看已有流量摘要...

Checking current context
  capture.status
  done: idle

────────────────────────
> Ask NetAgent...
```

Tradeoffs:
- Very clean.
- Debug visibility is lower.
- Best first implementation target.

### Layout B — Agent Thread + Context Rail

Best for:
- Wider terminal users.
- Keeping network context visible without making it primary.

Wide screen:

```text
┌ NetAgent ready · session:idle · capture:idle · pending:0 ─────────────────┐
│                                                     │ Context             │
│  > 最近一小时谁在用网络？                            │ iface      en0      │
│                                                     │ runstate   phase9   │
│                                                     │ capture    idle     │
│  我会先查看已有流量摘要...                           │                     │
│                                                     │ Activity            │
│  Checking current context                           │ permission.asked    │
│    capture.status                                   │ finding.created     │
│    done: idle                                       │                     │
│  permission required · medium risk                  │ permission.asked    │
│  [Y] once [A] always [N] reject [F] feedback        │ finding.created     │
│                                                     │                     │
├─────────────────────────────────────────────────────┴─────────────────────┤
│ > Ask NetAgent...                                                          │
└────────────────────────────────────────────────────────────────────────────┘
```

Narrow fallback:
- Collapse context rail.
- Use Layout A.

Tradeoffs:
- Good balance for desktop terminals.
- More implementation work.
- Context rail must be visually subdued.

### Layout C — Investigation Workspace

Best for:
- Later phases with richer tool/result display.
- Users comparing findings and artifacts while chatting.

Wide screen:

```text
┌ NetAgent ready · pending:0 ────────────────────────────────────────────────┐
│ Agent Thread                                      │ Evidence / Findings    │
│                                                   │                        │
│ > investigate suspicious DNS                      │ high  NXDOMAIN spike   │
│                                                   │ med   unusual TLS SNI  │
│                                                   │                        │
│ I found one DNS anomaly...                        │ pcap_001              │
│                                                   │ report_002            │
│ permission required                               │                        │
│ [Y] once [A] always [N] reject [F] feedback       │ Activity collapsed     │
├───────────────────────────────────────────────────┴────────────────────────┤
│ > Ask NetAgent...                                                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

Narrow fallback:
- Agent Thread only.
- Findings appear as a one-line strip above composer.

Tradeoffs:
- More powerful, but risks becoming dashboard-heavy again.
- Better after Phase 10/11 when persisted messages and tool parts exist.

### Layout D — Current Dashboard, Cleaned Up

Best for:
- Lowest-risk incremental migration from the current UI.
- Keeping most existing structure while reducing noise.

Wide screen:

```text
┌ NetAgent ready · session:idle · pending:0 ─────────────────────────────────┐
│ Summary                         │ Agent                                    │
│ capture idle                    │                                          │
│ iface en0                       │ > 最近一小时谁在用网络？                  │
│ findings 0                      │                                          │
│                                 │                                          │
│ permission.asked                │ 我会先查看已有流量摘要...                  │
│                                 │                                          │
├─────────────────────────────────┴──────────────────────────────────────────┤
│ > Ask NetAgent...                                                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

Tradeoffs:
- Easiest migration.
- Still less focused than Layout A/B.
- Useful if we want small PRs.

## Recommended Direction

Start with Layout A, then add Layout B's context rail only for wide terminals.

Reasoning:
- It best matches the Claude Code-style interaction goal.
- It naturally fixes the visual hierarchy problem.
- It reduces resize complexity.
- It keeps Phase 9 UI work scoped and avoids slipping into a full dashboard redesign.

Target behavior:

```text
width >= 110: Layout B
width < 110: Layout A
height < 22: compact thread, fewer messages, composer still visible
```

## Responsive Rules

Minimum supported terminal:
- Soft minimum: 80x24
- Hard fallback: below 70x18, show compact thread and a short warning line.

Rules:
- Composer is always last and visible.
- Status bar is one line where possible; compact to `NetAgent ready · pending:0` on narrow screens.
- Context rail appears only when width allows it.
- Activity drawer is collapsed by default.
- Long values are truncated based on available width, not a fixed global character limit.
- Fixed modal widths are avoided. Approval UI should fit current width.

## Visual Style

The visual language should be simple, restrained, and layered. It should feel like a professional terminal work surface, not a dashboard or chat app.

Palette:
- Background: near-black, not pure black.
- Primary text: off-white for assistant output and important values.
- Secondary text: slate gray for status, labels, and inactive context.
- User prompt marker: neutral light gray or off-white. Do not use bright color as decoration.
- Process heading: muted blue-gray or gray.
- Tool status: muted gray, with a small color accent only for lifecycle state.
- Permission/risk: amber. This is the strongest accent in normal operation.
- Error: orange/red only for actual failures.
- Success/completed: muted green, used sparingly.

Structure:
- Fewer borders.
- Prefer section spacing and text hierarchy over nested boxes.
- Avoid dashboard-card density.
- Keep status and debug text visually quiet.

Layering:
- Level 1: user prompt, assistant answer, permission request.
- Level 2: process headings such as `Plan`, `Checking`, `Reading`, `Summarizing`.
- Level 3: tool status lines and result summaries.
- Level 4: status bar, context rail, debug activity.

Spacing:
- Use blank lines between user prompt, assistant output, work trace, and permission request.
- Use indentation for tool calls instead of bordered cards.
- Avoid more than one prominent border in the main viewport.
- Keep the composer separated by a thin divider or spacing, not a heavy card.

Color discipline:
- One active accent at a time.
- Amber is reserved for permission/risk.
- Red/orange is reserved for failures.
- Green is reserved for completion, not for branding.
- Do not color every label; most hierarchy should come from spacing, indentation, and text weight/color contrast.

## Implementation Plan After Approval

1. Introduce layout helpers:
   - terminal width/height tracking if available from renderer.
   - layout variant selector: `single-thread`, `thread-with-rail`, `compact`.

2. Extract components:
   - `AppShell`
   - `CompactStatusBar`
   - `AgentThread`
   - `MessageItem`
   - `Composer`
   - `InlinePermissionCard`
   - `ContextRail`
   - `FindingsStrip`
   - `ActivityDrawer`

3. Replace current two-column dashboard layout:
   - Make conversation primary.
   - Move dashboard fields into status/context rail.
   - Collapse activity by default.

4. Add resize verification:
   - 120x36
   - 100x30
   - 80x24
   - 60x20

5. Preserve anti-drift invariants:
   - no direct `capture.start` / `capture.stop` UI control.
   - prompt submit still uses `canSubmitPrompt(state)`.
   - `viewMode` remains derived.

## Open Questions

- Should findings be always visible as a one-line strip, or only in the context rail?
- Should permission approval be inline in the thread immediately, or remain as an overlay for the first implementation?
- Should Activity be accessible through a keyboard toggle, or only shown in debug builds?
- Is 80x24 the minimum terminal size we want to support well?
- Do we want a separate "debug" visual mode later for protocol/method/event details?
