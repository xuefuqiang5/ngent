# NetAgent

This README only covers how to start the project locally.

## Prerequisites

- Rust toolchain
- Bun
- `tshark` on `PATH` if you want to parse `.pcap` files
- System privileges for live capture if you plan to use `tcpdump`-backed capture flows

## Start the Rust core

Run the core process from the repository root:

```bash
cargo run -p netagent-core
```

The core uses stdio JSON-RPC. You can verify that it starts correctly with:

```bash
printf '{"jsonrpc":"2.0","id":1,"method":"system.ping","params":{}}\n' | cargo run -q -p netagent-core
```

You can inspect the currently exposed methods with:

```bash
printf '{"jsonrpc":"2.0","id":1,"method":"core.capabilities","params":{}}\n' | cargo run -q -p netagent-core
```

## Start the OpenTUI app

Install UI dependencies and start the terminal app:

```bash
cd ui/opentui-app
bun install
bun run dev
```

You can also use:

```bash
bun run start
```

## Useful startup checks

From the repository root:

```bash
cargo test --workspace
```

If you want to open a local `.pcap` after the core is running:

```bash
printf '{"jsonrpc":"2.0","id":1,"method":"pcap.open","params":{"path":"/absolute/path/to/file.pcap"}}\n' | cargo run -q -p netagent-core
```
