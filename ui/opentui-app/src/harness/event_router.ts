import type { JsonRpcMessage, StdioTransport } from "./transport"

export type CoreEvent = {
  method: string
  params: unknown
}

export class EventRouter {
  private readonly events: CoreEvent[] = []
  private readonly listeners = new Set<(event: CoreEvent) => void>()

  constructor(transport: StdioTransport) {
    transport.onMessage((message) => this.handleMessage(message))
  }

  listEvents(): CoreEvent[] {
    return [...this.events]
  }

  onEvent(listener: (event: CoreEvent) => void): () => void {
    this.listeners.add(listener)
    return () => {
      this.listeners.delete(listener)
    }
  }

  private handleMessage(message: JsonRpcMessage): void {
    const method = message.method
    if (!method) {
      return
    }

    if (
      !method.startsWith("event.") &&
      !method.startsWith("session.") &&
      !method.startsWith("message.") &&
      !method.startsWith("agent.") &&
      !method.startsWith("permission.") &&
      !method.startsWith("artifact.") &&
      !method.startsWith("finding.") &&
      !method.startsWith("capture.") &&
      !method.startsWith("pcap.") &&
      !method.startsWith("flow.") &&
      !method.startsWith("dns.") &&
      !method.startsWith("tls.") &&
      !method.startsWith("http.") &&
      !method.startsWith("report.") &&
      !method.startsWith("alert.") &&
      !method.startsWith("zeek.") &&
      !method.startsWith("suricata.")
    ) {
      return
    }

    const event = {
      method,
      params: message.params ?? null,
    }
    this.events.push(event)

    for (const listener of this.listeners) {
      listener(event)
    }
  }
}
