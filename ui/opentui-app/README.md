# OpenTUI App

This package is the UI workspace for NetAgent.

Phase 0 only provides the package boundary, directory shape, and a placeholder entrypoint. It does not start the Rust Core, does not implement JSON-RPC transport, and does not render a real terminal UI yet.

Planned next work in Phase 1:

- `src/harness/transport.ts`: stdio transport.
- `src/harness/rpc_client.ts`: JSON-RPC client.
- `src/harness/event_router.ts`: core event routing.
- `src/app/renderer.ts`: minimal renderer bootstrap.

