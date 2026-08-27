# Suricata EVE Fixtures

JSON-lines `eve.json` produced by a real `suricata -r <pcap> -l <dir>` run
over the deterministic DNS fixture pcap, with additional hand-written
`event_type: alert` lines to exercise the alert parser.

Used by `tools/suricata.rs` parse tests (`parse_eve_json_lines`).
