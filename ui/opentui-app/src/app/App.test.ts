import { describe, expect, test } from "bun:test"
import type { KeyEvent } from "@opentui/core"
import { initialState } from "./state"
import { applyChatInputKey, reduceEvent } from "./App"

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
})

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
