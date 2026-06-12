# Case Model

Status: draft for Phase 10 planning

## Purpose

`Case` is NetAgent's business boundary for one security investigation. It is not a chat session and it is not raw state. It tells the agent what problem is being investigated, what scope applies, what evidence exists, what is still unknown, and what next actions are allowed or pending.

One sentence:

```text
Case manages the goal, scope, time window, evidence, findings, hypotheses, permission state, execution record, compact snapshot, and next actions for one investigation.
```

## Why Case Exists

NetAgent is a specialized security agent. It should not reuse information like a generic long-memory chatbot. It should reuse case-scoped investigation state:

- current user goal
- current network scope
- evidence already collected
- findings and hypotheses
- rejected or unverified assumptions
- permissions already requested, approved, or rejected
- next action candidates
- current compact snapshot

The agent plans, tool choices, permission requests, compacting, and answers should all be grounded in the active case.

## Core Boundaries

These concepts must not be collapsed into one another:

```text
Case != Session
Session != Evidence
Message != Finding
Snapshot != Full History
ModelContext != Database
```

- `Case` is the investigation boundary.
- `Session` is an interaction container.
- `Message` is an interaction record.
- `Evidence` is a fact source or reference.
- `Finding` is a security interpretation backed by evidence.
- `Snapshot` is a compact case summary for reuse.
- `ModelContext` is the temporary input prepared for one model call.

## Ownership

`Case` should eventually own or relate to:

```text
Case
  -> sessions
  -> messages and message_parts through sessions
  -> steps and tool_calls
  -> permission_requests
  -> artifacts
  -> evidence_refs
  -> observations
  -> findings
  -> hypotheses
  -> timeline_events
  -> investigation_snapshots
  -> reports and IOC exports
```

In Phase 10, only the minimal subset should be implemented:

```text
cases
sessions.case_id
investigation_snapshots
```

Do not block Phase 10 on a complete evidence graph.

## Data Shape

Initial Rust shape:

```rust
pub struct Case {
    pub id: CaseId,
    pub title: String,
    pub goal: String,
    pub status: CaseStatus,
    pub scope: CaseScope,
    pub time_window: TimeWindow,
    pub created_at: String,
    pub updated_at: String,
    pub closed_at: Option<String>,
}
```

Initial SQLite shape can store complex fields as JSON first:

```sql
CREATE TABLE cases (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  goal TEXT NOT NULL,
  status TEXT NOT NULL,
  scope_json TEXT NOT NULL,
  time_window_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  closed_at TEXT
);
```

## Status

Suggested `CaseStatus`:

```text
open
active
waiting_permission
waiting_evidence
analyzing
reporting
closed
archived
error
```

Status meaning:

- `open`: created, not yet actively running.
- `active`: current case for `agent.ask`.
- `waiting_permission`: blocked on a permission request.
- `waiting_evidence`: known evidence gap exists.
- `analyzing`: analysis or parsing is running.
- `reporting`: report or IOC export is running.
- `closed`: completed but still visible.
- `archived`: retained but not active.
- `error`: case is inconsistent or failed to recover.

Legal first-pass transitions:

```text
open -> active
active -> waiting_permission
waiting_permission -> active
waiting_permission -> waiting_evidence
active -> waiting_evidence
waiting_evidence -> active
active -> analyzing
analyzing -> active
active -> reporting
reporting -> active
active -> closed
closed -> archived
active -> error
waiting_permission -> error
analyzing -> error
reporting -> error
```

Do not use `CaseStatus` to replace lower-level runtime status. Tool calls, jobs, permissions, and agent steps still keep their own lifecycle.

## Scope

`CaseScope` describes where the investigation is allowed to look:

```rust
pub struct CaseScope {
    pub interfaces: Vec<String>,
    pub hosts: Vec<String>,
    pub filters: Vec<String>,
    pub pcap_artifacts: Vec<String>,
    pub tags: Vec<String>,
}
```

Scope changes are business-significant. They should update the case and be reflected in the next snapshot.

Examples:

- user narrows to `host=192.168.1.24`
- user changes time window to `last_1h`
- agent proposes `filter=dns`
- imported pcap becomes part of the investigation scope

## Time Window

```rust
pub struct TimeWindow {
    pub start: Option<String>,
    pub end: Option<String>,
    pub label: Option<String>,
}
```

Examples:

- `current_session`
- `last_1h`
- `pcap_capture_window`

Security findings without a time window should be treated as incomplete.

## Actions That Change Case

These actions should change the active case:

- user creates a new investigation goal
- user changes scope, interface, host, filter, or time window
- agent identifies an evidence gap
- tool produces an artifact, flow, DNS event, or timeline event
- analyzer creates or updates a finding
- permission request is created, approved, rejected, or revised
- agent run completes and updates the investigation snapshot
- report or IOC export is generated
- case is closed or archived

## Default Case Strategy

Phase 10 should not require full case selection UI. Use a default active case:

```text
case_default_current_network
```

Behavior:

- If `agent.ask` has no case id, use the current active case.
- If no active case exists, create the default active case.
- The default title can be `Current network investigation`.
- The first user prompt can populate `goal` if it is still empty.

This allows session persistence and snapshots to land without a full case manager.

## Phase 10 Minimum

Recommended implementation order:

```text
1. Add Case model in netagent-models.
2. Add cases table in SqliteStore.
3. Add sessions.case_id when session persistence lands.
4. Create or resolve default active case inside agent.ask.
5. Add investigation_snapshots table.
6. Update snapshot after each successful agent.ask.
```

Out of scope for the first pass:

- case switching UI
- multi-case search
- full evidence graph
- cross-case memory
- external intelligence
- live capture as an LLM tool

## Open Questions

- Should a user prompt always update `Case.goal`, or only when the case has no goal?
- Should imported pcap files create a new case by default?
- Should live capture always bind to the active case, or can it create a child case?
- What is the recovery rule if Core restarts while a case is `waiting_permission`?
