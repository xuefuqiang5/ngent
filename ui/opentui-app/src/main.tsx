import React from "react"
import { createCliRenderer } from "@opentui/core"
import { createRoot } from "@opentui/react"
import { App } from "./app/App"
import { createStdioTransport } from "./harness/transport"
import { RpcClient } from "./harness/rpc_client"
import { EventRouter } from "./harness/event_router"
import { coreDevCommand } from "./harness/process_manager"

async function main(): Promise<void> {
  const transport = await createStdioTransport(coreDevCommand())
  const rpc = new RpcClient(transport)
  const eventRouter = new EventRouter(transport)

  const renderer = await createCliRenderer({
    exitOnCtrlC: true,
    targetFps: 30,
  })

  createRoot(renderer).render(
    <App eventRouter={eventRouter} rpc={rpc} transport={transport} />,
  )
}

void main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error)
  console.error(`NetAgent UI failed: ${message}`)
  process.exitCode = 1
})
