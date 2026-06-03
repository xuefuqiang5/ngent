# Schemas

Shared JSON schemas for stable protocol surfaces.

## Phase 8 Reports

- `report-generate-result.schema.json` describes the `report.generate` JSON-RPC result.
- `ioc-export-result.schema.json` describes the `ioc.export` JSON-RPC result.

Both result shapes return bounded metadata and artifact references. Full Markdown reports, IOC JSON documents, pcap files, raw tool output, and other large evidence remain artifacts referenced by `artifact.path`.
