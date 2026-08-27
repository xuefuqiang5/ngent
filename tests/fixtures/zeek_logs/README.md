# Zeek Log Fixtures

JSON-lines logs produced by a real `zeek -C -r <pcap>` run (with
`redef LogAscii::use_json=T;`) over the deterministic DNS fixture pcap
(`cargo run -q -p netagent-core --example gen_fixture`), trimmed to a few
records:

- `conn.log` — zeek connection records (JSON lines), `id.orig_h` is the
  connection initiator.
- `dns.log` — zeek DNS records (JSON lines), `id.orig_h` is the querying
  client.

Used by `tools/zeek.rs` parse tests (`parse_conn_log` / `parse_dns_log`).
