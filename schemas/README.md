# Schemas

Shared JSON schemas for stable protocol surfaces.

## Phase 8 Reports

- `report-generate-result.schema.json` describes the `report.generate` JSON-RPC result.
- `ioc-export-result.schema.json` describes the `ioc.export` JSON-RPC result.

Both result shapes return bounded metadata and artifact references. Full Markdown reports, IOC JSON documents, pcap files, raw tool output, and other large evidence remain artifacts referenced by `artifact.path`.

## Phase 10 Session Recovery

- `session-list-result.schema.json` describes the `session.list` JSON-RPC result.
- `session-snapshot-result.schema.json` describes the complete `session.get` recovery snapshot: messages, normalized message parts, steps, bounded tool-call metadata, and pending permission requests.

The snapshot contains references and bounded text only. It never embeds PCAP data or raw tool output.

`reasoning` message parts contain only the bounded goal/execution-plan summary displayed in the UI; hidden chain-of-thought is never persisted.
