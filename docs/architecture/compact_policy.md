# Compact Policy And Investigation Snapshot

Status: draft for Phase 10 planning

## Purpose

NetAgent needs compacting, but not generic chat summarization. It needs case-aware investigation compaction that preserves evidence, permission decisions, uncertainty, and next actions.

One sentence:

```text
Compact turns full runtime history into a structured InvestigationSnapshot for the active case, without losing evidence refs, permission state, scope, or uncertainty.
```

## Why Generic Compact Is Not Enough

Generic agent compact often does this:

```text
old conversation -> natural language summary
```

NetAgent must do this:

```text
case state + evidence + findings + runtime history
  -> structured investigation snapshot
  -> bounded model context
```

Security analysis cannot summarize away:

- time window
- scope
- evidence refs
- permission decisions
- rejected hypotheses
- uncertainty
- raw-output boundaries

## Snapshot Shape

Initial conceptual shape:

```rust
pub struct InvestigationSnapshot {
    pub id: String,
    pub case_id: String,
    pub session_id: Option<String>,
    pub version: u64,
    pub user_goal: String,
    pub scope: SnapshotScope,
    pub time_window: SnapshotTimeWindow,
    pub confirmed_facts: Vec<SnapshotFact>,
    pub hypotheses: Vec<SnapshotHypothesis>,
    pub open_questions: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub completed_steps: Vec<SnapshotStep>,
    pub pending_permissions: Vec<String>,
    pub next_actions: Vec<SnapshotNextAction>,
    pub uncertainty: Vec<String>,
    pub created_at: String,
}
```

Phase 10 SQLite can start with JSON:

```sql
CREATE TABLE investigation_snapshots (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  session_id TEXT,
  version INTEGER NOT NULL,
  summary_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
```

## Snapshot Sections

### User Goal

The current business question.

Example:

```text
Identify who used the network in the last hour.
```

### Scope

The investigation boundary:

- interfaces
- hosts
- filters
- pcap artifacts
- tags

### Time Window

Must be explicit when available:

- `last_1h`
- capture start/end
- pcap time range

If no time window exists, the snapshot should mark the analysis as incomplete.

### Confirmed Facts

Facts must be tied to evidence refs.

```json
{
  "fact": "No active capture is running.",
  "evidence_refs": ["capture.status:latest"],
  "confidence": "high"
}
```

### Hypotheses

Hypotheses are not facts.

```json
{
  "statement": "Host 192.168.1.24 may be the top talker.",
  "status": "open",
  "evidence_refs": [],
  "confidence": "low"
}
```

Suggested statuses:

```text
open
supported
rejected
superseded
```

### Completed Steps

Short record of what the agent did:

```json
{
  "step": "Checked capture status",
  "result_summary": "No active capture is running.",
  "tool_calls": ["call_001"]
}
```

### Pending Permissions

Permission state must be preserved exactly enough for recovery:

```json
{
  "request_id": "per_001",
  "permission": "capture_live",
  "risk": "medium",
  "scope": ["en0", "dns"],
  "status": "pending"
}
```

### Next Actions

The agent's next safe options:

```json
{
  "summary": "Request 30s DNS capture on en0.",
  "requires_permission": true,
  "permission": "capture_live"
}
```

### Uncertainty

State what is unknown and why:

```json
{
  "unknown": "Current top talker",
  "reason": "No recent live capture or flow snapshot exists."
}
```

## Compact Triggers

Phase 10 triggers:

- after each successful `agent.ask`
- after permission reply changes case state
- after a finding is created
- before a long model context would exceed budget

Later triggers:

- after tool result is appended
- after report generation
- after capture completes
- before session close

## Compact Inputs

Context should be built from:

```text
active case
last active snapshot
recent messages
steps and tool calls
permission requests
findings
artifacts and evidence refs
bounded network summaries
```

Do not include:

```text
raw pcap
raw tshark JSON
raw stdout/stderr
high-frequency packet events
secret values
hidden model reasoning
```

## Compact Output Rules

Compact must:

- preserve evidence refs exactly
- preserve permission request IDs and decisions
- preserve scope and time window
- preserve rejected hypotheses when relevant
- distinguish facts from model-generated conclusions
- preserve uncertainty
- keep raw data as artifact refs only

Compact must not:

- convert model text into evidence
- omit rejected permission state
- omit pending evidence gaps
- include raw command output
- include hidden reasoning transcript

## ContextBuilder Contract

`ContextBuilder` should construct the model input for one agent turn.

Inputs:

```text
case
active snapshot
current user prompt
last N messages
pending permissions
relevant findings
relevant evidence refs
allowed tools for current phase and agent mode
```

Output:

```text
ModelContext
  system instructions
  current user prompt
  case summary
  evidence summaries
  uncertainty
  next action constraints
  recent conversation window
  allowed tool schemas
```

`ModelContext` is temporary and should not be treated as database truth.

## Phase 10 Minimum

First implementation target:

```text
1. Persist sessions, messages, and message_parts.
2. Add cases table and default active case.
3. Add investigation_snapshots table with summary_json.
4. After agent.ask, write a minimal snapshot:
   - user_goal
   - scope
   - confirmed_facts
   - evidence_refs
   - open_questions
   - next_actions
5. Add a ContextBuilder skeleton that can use snapshot + last N messages.
```

Minimal snapshot JSON:

```json
{
  "user_goal": "",
  "scope": {},
  "time_window": {},
  "confirmed_facts": [],
  "hypotheses": [],
  "open_questions": [],
  "evidence_refs": [],
  "completed_steps": [],
  "pending_permissions": [],
  "next_actions": [],
  "uncertainty": []
}
```

## Recovery Rules

On Core restart:

- latest active snapshot is reusable
- running steps become `aborted` or `error`
- pending permission requests remain pending if persisted
- active capture jobs must be reconciled by RunState/Job recovery
- model context must be rebuilt from persisted state, not from UI memory

## Open Questions

- Should compact be deterministic first, model-assisted later, or always deterministic?
- Should snapshots be versioned by schema version?
- How many snapshots should be retained per case?
- Should `reject_with_feedback` update open questions or next actions automatically?
