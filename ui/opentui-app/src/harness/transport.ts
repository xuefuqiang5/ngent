import { spawn } from "node:child_process"

export type JsonRpcMessage = {
  jsonrpc: "2.0"
  id?: string | number | null
  method?: string
  params?: unknown
  result?: unknown
  error?: {
    code: number
    message: string
  }
}

export type StdioTransport = {
  send(message: JsonRpcMessage): void
  close(): Promise<void>
  onMessage(handler: (message: JsonRpcMessage) => void): void
}

function parseLine(line: string): JsonRpcMessage | null {
  const trimmed = line.trim()
  if (!trimmed) {
    return null
  }

  return JSON.parse(trimmed) as JsonRpcMessage
}

export async function createStdioTransport(
  command: string[],
): Promise<StdioTransport> {
  const proc = spawn(command[0], command.slice(1), {
    stdio: ["pipe", "pipe", "inherit"],
  })

  const handlers = new Set<(message: JsonRpcMessage) => void>()
  let buffer = ""

  proc.stdout.on("data", (chunk: Buffer | string) => {
    buffer += chunk.toString()

    while (true) {
      const newlineIndex = buffer.indexOf("\n")
      if (newlineIndex === -1) {
        break
      }

      const line = buffer.slice(0, newlineIndex)
      buffer = buffer.slice(newlineIndex + 1)

      const message = parseLine(line)
      if (!message) {
        continue
      }

      for (const handler of handlers) {
        handler(message)
      }
    }
  })

  return {
    send(message) {
      proc.stdin.write(`${JSON.stringify(message)}\n`)
    },
    onMessage(handler) {
      handlers.add(handler)
    },
    async close() {
      proc.stdin.end()
      await new Promise<void>((resolve, reject) => {
        proc.once("exit", () => resolve())
        proc.once("error", (error) => reject(error))
      })
    },
  }
}
