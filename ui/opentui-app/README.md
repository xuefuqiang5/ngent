# OpenTUI App

This package is the UI workspace for NetAgent.

The Phase 11 UI is a single-screen investigation workspace backed by the Rust Core over stdio JSON-RPC. It shows the active model, Agent tool allowlist, persisted goal analysis/plan, read-only tool calls and bounded result summaries, findings, capture status, and permission requests.

Current recovery behavior:

- On startup, the UI calls `session.list` and restores the latest `session.get` snapshot.
- Persisted user/assistant messages, goal plans, tool-call status, and tool-result summaries are rendered again after Core/UI restart.
- Pending permission requests are restored through `permission.list_pending` and continue to block prompt submission.
- UI state remains read-only with respect to system operations; all execution and risk decisions stay in Rust Core.

Run checks from this directory:

```bash
bun test
./node_modules/typescript/bin/tsc --noEmit
```
