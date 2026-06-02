import type { JsonRpcMessage, StdioTransport } from "./transport"

type PendingRequest = {
  resolve: (value: unknown) => void
  reject: (error: Error) => void
}

export class RpcClient {
  private readonly pending = new Map<string, PendingRequest>()
  private nextId = 1

  constructor(private readonly transport: StdioTransport) {
    this.transport.onMessage((message) => this.handleMessage(message))
  }

  request(method: string, params: unknown = {}): Promise<unknown> {
    const id = String(this.nextId++)

    this.transport.send({
      jsonrpc: "2.0",
      id,
      method,
      params,
    })

    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject })
    })
  }

  private handleMessage(message: JsonRpcMessage): void {
    if (message.id === undefined || message.id === null) {
      return
    }

    const key = String(message.id)
    const pending = this.pending.get(key)
    if (!pending) {
      return
    }

    this.pending.delete(key)

    if (message.error) {
      pending.reject(
        new Error(`RPC ${message.error.code}: ${message.error.message}`),
      )
      return
    }

    pending.resolve(message.result)
  }
}
