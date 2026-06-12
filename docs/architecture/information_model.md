# Information Model

Status: draft for Phase 10 planning

## Purpose

NetAgent handles many kinds of information: user messages, tool outputs, artifacts, flows, findings, permissions, snapshots, and reports. These items cannot be treated as plain text. Each important item needs identity, source, sensitivity, visibility, trust level, retention policy, compact policy, and lifecycle.

One sentence:

```text
Every important information item must declare what it is, where it came from, how trustworthy it is, who may see it, how it may be compacted, and how long it should be retained.
```

## Why This Matters

Without information policy, the agent will eventually:

- put raw packet data into model context
- confuse model-generated text with observed evidence
- lose permission decisions during compaction
- summarize away evidence refs
- expose debug payloads as product UI
- keep ephemeral tool progress as if it were durable case state

Information policy prevents those failures.

## Core Shape

This is the conceptual shape, not necessarily one database table:

```rust
pub struct InformationItem {
    pub id: String,
    pub case_id: Option<String>,
    pub kind: InformationKind,
    pub source: InformationSource,
    pub sensitivity: Sensitivity,
    pub trust_level: TrustLevel,
    pub visibility: Visibility,
    pub compact_policy: CompactPolicy,
    pub retention_policy: RetentionPolicy,
    pub lifecycle: InformationLifecycle,
    pub evidence_refs: Vec<String>,
    pub created_at: String,
}
```

Do not implement a universal `information_items` table in the first pass. Start with enums and metadata fields that can be attached to `message_parts`, `tool_calls`, `permission_requests`, `artifacts`, `findings`, and `snapshots`.

## Kinds

Suggested `InformationKind`:

```text
user_prompt
assistant_output
agent_plan_summary
agent_progress_summary
tool_call
tool_result_summary
permission_request
permission_reply
artifact_ref
raw_artifact
flow
dns_event
tls_event
http_event
timeline_event
observation
finding
hypothesis
evidence_summary
report
ioc_export
investigation_snapshot
debug_event
```

## Source

Suggested `InformationSource`:

```text
user
assistant
model
core
tool
analyzer
artifact_store
sqlite_store
live_capture
imported_pcap
report_generator
permission_manager
```

Source affects trust. For example, `live_capture` and parsed store events are observed or derived facts; `model` content is generated and must not become evidence without backing refs.

## Sensitivity

Suggested `Sensitivity`:

```text
public_summary
internal
sensitive
raw_evidence
secret
```

Examples:

| Item | Sensitivity |
| --- | --- |
| finding summary | `public_summary` |
| artifact id | `public_summary` |
| permission command preview | `sensitive` |
| pcap file | `raw_evidence` |
| tshark JSON | `raw_evidence` |
| tcpdump stdout or stderr | `raw_evidence` |
| API key or env secret | `secret` |
| tool progress message | `internal` |

Rules:

- `secret` is never persisted into case state or model context.
- `raw_evidence` is stored as artifact or structured store, not model context.
- `sensitive` requires explicit policy before report/model exposure.

## Trust Level

Suggested `TrustLevel`:

```text
observed
derived
inferred
user_claimed
model_generated
system_reported
```

Meaning:

- `observed`: directly observed by capture/imported data.
- `derived`: parsed or transformed from observed data.
- `inferred`: analyzer or agent inference from evidence.
- `user_claimed`: asserted by the user.
- `model_generated`: produced by LLM text.
- `system_reported`: status from Core/runtime.

Rules:

- Findings should be `inferred` and carry evidence refs.
- Flow and DNS events are usually `derived`.
- Assistant answers are `model_generated`.
- Model-generated text must not become `observed`.

## Visibility

```rust
pub struct Visibility {
    pub ui: bool,
    pub model: bool,
    pub report: bool,
    pub debug: bool,
}
```

Defaults:

| Kind | UI | Model | Report | Debug |
| --- | --- | --- | --- | --- |
| user_prompt | yes | yes | no | yes |
| assistant_output | yes | context-dependent | no | yes |
| tool_result_summary | yes | yes | yes | yes |
| raw_artifact | no | no | ref only | yes |
| finding | yes | yes | yes | yes |
| permission_request | yes | summary only | audit only | yes |
| debug_event | no | no | no | yes |
| investigation_snapshot | no | yes | no | yes |

## Compact Policy

Suggested `CompactPolicy`:

```text
keep_exact
summarize
keep_ref_only
drop_after_run
never_to_model
```

Examples:

| Item | Policy |
| --- | --- |
| permission request and reply | `keep_exact` |
| finding | `keep_exact` and `summarize` |
| evidence ref | `keep_exact` |
| pcap artifact | `keep_ref_only` |
| tshark JSON artifact | `keep_ref_only` |
| flow list | `summarize` |
| tool progress | `drop_after_run` |
| raw stdout/stderr | `keep_ref_only` or `never_to_model` |
| hidden model reasoning | `never_to_model` |

## Retention Policy

Suggested `RetentionPolicy`:

```text
ephemeral
session_lifetime
case_lifetime
project_lifetime
audit_lifetime
```

Examples:

- tool progress: `session_lifetime`
- permission decisions: `audit_lifetime`
- finding: `case_lifetime`
- artifact: `case_lifetime`
- approved always rules: `project_lifetime`
- secrets: not stored

## Lifecycle

Suggested `InformationLifecycle`:

```text
active
superseded
rejected
confirmed
archived
deleted
```

Examples:

- hypothesis can move from `active` to `confirmed` or `rejected`.
- snapshot can move from `active` to `superseded`.
- permission request can move from `active` to `confirmed` or `rejected`.

## Initial Implementation Strategy

Do not build a universal information registry first.

Phase 10 first pass:

```text
1. Define enums in netagent-models/src/information.rs.
2. Add metadata_json to message_parts and tool_calls.
3. Add information policy fields only where immediately useful:
   - message_parts.kind
   - message_parts.metadata_json
   - tool_calls.result_summary
   - investigation_snapshots.summary_json
4. Keep raw evidence in ArtifactStore and structured SQLite tables.
```

Later phases:

```text
1. Add policy fields to artifacts and findings.
2. Add explicit evidence_refs on findings and tool results.
3. Add ContextBuilder filters by sensitivity, visibility, and compact_policy.
4. Add audit queries for permission and sensitive actions.
```

## Hard Rules

- Raw packet streams never enter UI or model context.
- Large stdout/stderr never enter model context.
- LLM text is not evidence unless backed by evidence refs.
- Compact must preserve evidence refs and permission decisions.
- UI may show summaries and refs, not raw evidence by default.
- Reports must include traceable evidence references.

## Open Questions

- Should `Visibility` be stored as booleans or derived from kind plus sensitivity?
- Should `TrustLevel` be mandatory on all message parts, or only on evidence-like parts?
- Should reports ever include `sensitive` command previews?
- Should rejected hypotheses be visible in user-facing summaries, or only in debug/audit?
