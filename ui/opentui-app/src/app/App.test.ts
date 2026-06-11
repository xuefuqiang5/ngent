import { describe, expect, test } from "bun:test"
import type { KeyEvent } from "@opentui/core"
import {
  canSubmitPrompt,
  deriveViewMode,
  initialState,
  type AppState,
} from "./state"
import { applyChatInputKey, reduceEvent, summarizeCoreEvent } from "./App"

describe("App event reducer", () => {
  test("upserts duplicate finding events by id", () => {
    const first = reduceEvent(initialState(), {
      method: "finding.created",
      params: {
        id: "finding_mock_0001",
        severity: "low",
        title: "First finding",
        summary: "Initial summary",
      },
    })

    const second = reduceEvent(first, {
      method: "finding.created",
      params: {
        id: "finding_mock_0001",
        severity: "medium",
        title: "Updated finding",
        summary: "Updated summary",
      },
    })

    expect(second.alerts).toHaveLength(1)
    expect(second.alerts[0]).toEqual({
      id: "finding_mock_0001",
      severity: "medium",
      title: "Updated finding",
      summary: "Updated summary",
    })
  })

  test("normalizes nested core finding payloads", () => {
    const state = reduceEvent(initialState(), {
      method: "finding.created",
      params: {
        finding: {
          id: "finding_0001",
          severity: "high",
          title: "NXDOMAIN spike",
          description: "Host produced repeated NXDOMAIN responses.",
        },
      },
    })

    expect(state.alerts[0]).toEqual({
      id: "finding_0001",
      severity: "high",
      title: "NXDOMAIN spike",
      summary: "Host produced repeated NXDOMAIN responses.",
    })
  })

  test("applies printable chat input keys and ignores control shortcuts", () => {
    let value = ""
    value = applyChatInputKey(value, key("h"))
    value = applyChatInputKey(value, key("i"))
    value = applyChatInputKey(value, key("space"))
    value = applyChatInputKey(value, key("a", { shift: true }))
    value = applyChatInputKey(value, key("backspace"))
    value = applyChatInputKey(value, key("r", { ctrl: true }))

    expect(value).toBe("hi ")
  })

  test("derives approval mode from pending permission only", () => {
    const state = reduceEvent(
      {
        ...readyState(),
        session: {
          ...readyState().session,
          status: "busy",
        },
      },
      {
        method: "permission.asked",
        params: {
          request: {
            id: "permission_0001",
            session_id: "session_0001",
            permission: "capture.start",
            risk: "medium",
            patterns: ["en0"],
            metadata: {
              tool: "capture.start",
              command_preview: "tcpdump -i en0",
              reason: "Investigate live traffic.",
            },
          },
        },
      },
    )

    expect(deriveViewMode(state)).toBe("approval")
    expect(canSubmitPrompt(state)).toBe(false)
  })

  test("allows prompt submission only when sync is ready and session is idle", () => {
    const ready = readyState()
    const syncing = {
      ...ready,
      sync: { status: "syncing" as const },
    }
    const error = {
      ...ready,
      sync: { status: "error" as const, error: "core unavailable" },
    }
    const busy = {
      ...ready,
      session: { ...ready.session, status: "busy" as const },
    }

    expect(canSubmitPrompt(ready)).toBe(true)
    expect(canSubmitPrompt(syncing)).toBe(false)
    expect(canSubmitPrompt(error)).toBe(false)
    expect(canSubmitPrompt(busy)).toBe(false)
    expect(deriveViewMode(error)).toBe("syncing")
  })

  test("summarizes tool events as bounded work trace items", () => {
    expect(
      summarizeCoreEvent({
        method: "agent.tool.called",
        params: {
          tool_call: {
            tool_name: "flow.list",
            input: { limit: 20 },
          },
        },
      }),
    ).toEqual({
      title: "Running tool",
      detail: "flow.list",
      status: "running",
    })
  })

  test("does not promote raw message events into work trace", () => {
    expect(
      summarizeCoreEvent({
        method: "message.created",
        params: {
          message: {
            id: "msg_0001",
            parts: [{ content: "raw message payload" }],
          },
        },
      }),
    ).toBe(null)
  })
})

function readyState(): AppState {
  return {
    ...initialState(),
    sync: { status: "ready" },
  }
}

function key(
  name: string,
  options: Partial<Pick<KeyEvent, "ctrl" | "meta" | "shift" | "sequence">> = {},
): KeyEvent {
  return {
    name,
    ctrl: options.ctrl ?? false,
    meta: options.meta ?? false,
    shift: options.shift ?? false,
    sequence: options.sequence ?? (name.length === 1 ? name : ""),
  } as KeyEvent
}
