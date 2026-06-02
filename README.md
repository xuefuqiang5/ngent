# NetAgent

NetAgent is a permission-aware network monitoring and analysis TUI agent. It pairs an OpenTUI/Bun UI process with a Rust Core process over stdio JSON-RPC.

Current status: `Phase 7 - Parsing and First Finding`

## Completed phases

| Phase | Name | Status |
|-------|------|--------|
| 0 | Workspace Skeleton | Done |
| 1 | Protocol and Harness | Done |
| 2 | Agent Runtime Foundation | Done |
| 3 | Permission State Machine | Done |
| 4 | Tool Runtime and Artifact Store | Done |
| 5 | UI Minimal Views | Done |
| 6 | Real Capture MVP | Done |
| 7 | Parsing and First Finding | Done |

## Current capabilities

- **Rust Core**: 18 JSON-RPC methods, real tcpdump capture path, tshark-based pcap parsing, SQLite persistence, NXDOMAIN spike detection, permission state machine, tool runtime with artifact refs.
- **UI**: OpenTUI React dashboard with activity stream, alerts/findings panel, approval modal, agent prompt, and capture state fields.

## Workspace layout

- `crates/netagent-core`: Rust core process (JSON-RPC server, capture, parsing, storage, analysis)
- `crates/netagent-models`: shared Rust data models (Flow, DnsEvent, Finding, EvidenceRef, etc.)
- `ui/opentui-app`: Bun/OpenTUI UI workspace
- `config/`: example configuration files
- `rules/builtin/`: starter detection rules
- `schemas/`: JSON schemas
- `examples/`: example pcaps and configs
- `tests/`: test fixtures

## Development

### Rust

```bash
cargo check
cargo test
cargo run -p netagent-core
```

### UI

```bash
cd ui/opentui-app
bun install
bunx tsc --noEmit
bun run src/main.ts
```

### Quick verification

```bash
# Ping
printf '{"jsonrpc":"2.0","id":1,"method":"system.ping","params":{}}\n' | cargo run -q -p netagent-core

# Capabilities
printf '{"jsonrpc":"2.0","id":1,"method":"core.capabilities","params":{}}\n' | cargo run -q -p netagent-core

# List stored flows
printf '{"jsonrpc":"2.0","id":1,"method":"flow.list","params":{}}\n' | cargo run -q -p netagent-core

# List stored findings
printf '{"jsonrpc":"2.0","id":1,"method":"finding.list","params":{}}\n' | cargo run -q -p netagent-core
```

## Known caveats

- Live capture (`tcpdump`) requires permissions not available on this machine (`/dev/bpf0: Operation not permitted`).
- End-to-end pcap parsing test requires a pcap file with DNS traffic; tshark is installed and ready.
- Phase 7 compiles with zero warnings; Rust unit tests pass.

## Next gate

`Phase 8: Reports` — Markdown report generation, IOC export, evidence bundle metadata.
