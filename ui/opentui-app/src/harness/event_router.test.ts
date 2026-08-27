import { describe, expect, test } from "bun:test"
import { EventRouter } from "./event_router"
import type { JsonRpcMessage, StdioTransport } from "./transport"

function createMockTransport() {
  const handlers = new Set<(message: JsonRpcMessage) => void>()
  const transport: StdioTransport = {
    send() {},
    async close() {},
    onMessage(handler) {
      handlers.add(handler)
    },
  }

  return {
    transport,
    emit(message: JsonRpcMessage) {
      for (const handler of handlers) {
        handler(message)
      }
    },
  }
}

describe("EventRouter", () => {
  test("routes network and report domain events", () => {
    const mock = createMockTransport()
    const router = new EventRouter(mock.transport)
    const seen: string[] = []

    router.onEvent((event) => {
      seen.push(event.method)
    })

    mock.emit({ jsonrpc: "2.0", id: 1, result: { ok: true } })
    mock.emit({ jsonrpc: "2.0", method: "flow.created", params: { count: 2 } })
    mock.emit({ jsonrpc: "2.0", method: "dns.observed", params: { count: 2 } })
    mock.emit({
      jsonrpc: "2.0",
      method: "report.generated",
      params: { metadata: { finding_count: 1 } },
    })
    mock.emit({
      jsonrpc: "2.0",
      method: "zeek.processed",
      params: { flows_parsed: 6, dns_parsed: 8 },
    })
    mock.emit({
      jsonrpc: "2.0",
      method: "suricata.processed",
      params: { alerts_parsed: 4 },
    })
    mock.emit({ jsonrpc: "2.0", method: "alert.created", params: { alert: { id: "a1" } } })

    expect(seen).toEqual([
      "flow.created",
      "dns.observed",
      "report.generated",
      "zeek.processed",
      "suricata.processed",
      "alert.created",
    ])
    expect(router.listEvents().map((event) => event.method)).toEqual(seen)
  })
})
