import { describe, expect, test } from "bun:test"
import type { KeyEvent } from "@opentui/core"
import {
  canSubmitPrompt,
  deriveViewMode,
  initialState,
  type AppState,
} from "./state"
import {
  applyChatInputKey,
  formatTuiModelText,
  removeLastGrapheme,
  responsiveDensity,
  sanitizeDisplayText,
  sanitizePastedText,
  upsertChatMessage,
  readLatestSession,
  readRestoredChatMessages,
  readRestoredToolEvents,
  reduceEvent,
  summarizeCoreEvent,
  truncateForDisplay,
} from "./App"

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

  test("accepts Chinese IME paste and removes a complete grapheme", () => {
    expect(sanitizePastedText("你好\r\n网络\u0000")).toBe("你好\n网络")
    expect(removeLastGrapheme("检查网络🧑‍💻")).toBe("检查网络")
    expect(removeLastGrapheme("检查")).toBe("检")
    expect(truncateForDisplay("A🧑‍💻中文B", 4)).toBe("A🧑‍💻中文...")
  })

  test("reduces visible history when the terminal is resized", () => {
    expect(responsiveDensity(120, 40)).toEqual({
      compact: false,
      messageLimit: 8,
      traceLimit: 8,
    })
    expect(responsiveDensity(60, 20)).toEqual({
      compact: true,
      messageLimit: 4,
      traceLimit: 3,
    })
    expect(responsiveDensity(50, 12)).toEqual({
      compact: true,
      messageLimit: 2,
      traceLimit: 1,
    })
  })

  test("upserts the same assistant message delivered by event and RPC", () => {
    const message = {
      id: "msg_assistant_0001",
      role: "assistant" as const,
      status: "sent" as const,
      content: "one response",
    }
    const once = upsertChatMessage([], message)
    const twice = upsertChatMessage(once, { ...message, content: "final response" })

    expect(twice).toHaveLength(1)
    expect(twice[0]?.content).toBe("final response")
  })

  test("keeps the core message id when committing an assistant event", () => {
    const state = reduceEvent(readyState(), {
      method: "message.created",
      params: {
        message: {
          id: "msg_core_0001",
          role: "assistant",
          parts: [{ kind: "text", content: "answer" }],
        },
      },
    })

    expect(state.session.messages.at(-1)?.id).toBe("msg_core_0001")
  })

  test("formats bounded Markdown as safe terminal text", () => {
    const markdown = [
      "# 检查结果",
      "",
      "- **状态**：正常",
      "| 项目 | 结果 |",
      "| --- | --- |",
      "| DNS | `ok` |",
      "```sh",
      "echo safe",
      "```",
    ].join("\n")

    expect(formatTuiModelText(markdown, 5)).toBe(
      "检查结果\n\n• 状态：正常\n项目 · 结果\nDNS · ok\n… output shortened for this view",
    )
    expect(sanitizeDisplayText("ok\u001b[31m\ttext")).toBe("ok  text")
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

  test("summarizes persisted goal analysis without exposing hidden reasoning", () => {
    const [event] = readRestoredToolEvents({
      messages: [
        {
          id: "msg_plan_0001",
          role: "assistant",
          parts: [
            {
              id: "part_plan_0001",
              kind: "reasoning",
              content: JSON.stringify({
                objective: "Inspect stored evidence",
                selected_tools: ["flow.list", "finding.list"],
              }),
            },
          ],
        },
      ],
      tool_calls: [],
    })

    expect(summarizeCoreEvent(event)).toEqual({
      title: "Goal analyzed",
      detail: "Inspect stored evidence · plan: flow.list, finding.list",
      status: "done",
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

  test("reads latest persisted session from core payload", () => {
    expect(
      readLatestSession({
        sessions: [
          {
            id: "ses_0002",
            mode: "observe",
            run_state: "idle",
            max_steps: 8,
          },
          {
            id: "ses_0001",
            mode: "observe",
          },
        ],
      }),
    ).toEqual({
      id: "ses_0002",
      mode: "observe",
      run_state: "idle",
      max_steps: 8,
    })
  })

  test("converts persisted messages into bounded chat messages", () => {
    expect(
      readRestoredChatMessages({
        messages: [
          {
            id: "msg_0001",
            role: "user",
            parts: [{ id: "part_0001", kind: "text", content: "hello" }],
          },
          {
            id: "msg_0002",
            role: "assistant",
            parts: [
              { id: "part_0002", kind: "tool_call", content: "hidden" },
              { id: "part_0003", kind: "text", content: "hi there" },
            ],
          },
          {
            id: "msg_0003",
            role: "tool",
            parts: [{ id: "part_0004", kind: "text", content: "tool result" }],
          },
        ],
      }),
    ).toEqual([
      {
        id: "msg_0001",
        role: "user",
        status: "sent",
        content: "hello",
      },
      {
        id: "msg_0002",
        role: "assistant",
        status: "sent",
        content: "hi there",
      },
      {
        id: "msg_0003",
        role: "system",
        status: "sent",
        content: "tool result",
      },
    ])
  })

  test("restores persisted tool lifecycle as bounded work trace events", () => {
    const events = readRestoredToolEvents({
      messages: [
        {
          id: "msg_tool_result_0001",
          role: "tool",
          parts: [
            {
              id: "part_tool_result_0001",
              kind: "tool_result",
              content: JSON.stringify({
                call_id: "call_0001",
                result: {
                  summary: "Found 3 stored flows; returned 3.",
                },
              }),
            },
          ],
        },
      ],
      tool_calls: [
        {
          id: "call_0001",
          tool_name: "flow.list",
          input: '{"limit":20}',
          status: "completed",
        },
        {
          id: "call_0002",
          tool_name: "capture.start",
          input: '{"duration":10}',
          status: "pending",
        },
        {
          id: "call_0003",
          tool_name: "artifact.summary",
          input: "{}",
          status: "aborted",
        },
      ],
    })

    expect(events.map(summarizeCoreEvent)).toEqual([
      {
        title: "Tool completed",
        detail: "flow.list · Found 3 stored flows; returned 3.",
        status: "done",
      },
      {
        title: "Running tool",
        detail: "capture.start",
        status: "running",
      },
      {
        title: "Tool did not complete",
        detail: "artifact.summary",
        status: "error",
      },
    ])
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
