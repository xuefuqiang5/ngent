import type { PendingApproval } from "../app/state"

export function ApprovalModal(props: {
  request?: PendingApproval
  visible: boolean
}) {
  if (!props.visible || !props.request) {
    return null
  }

  return (
    <box
      position="absolute"
      right={2}
      top={2}
      width={48}
      borderStyle="double"
      borderColor="#f59e0b"
      backgroundColor="#1f2937"
      padding={1}
      flexDirection="column"
      gap={1}
    >
      <text fg="#f8fafc">Approval Required</text>
      <text fg="#f59e0b">
        {props.request.permission} / {props.request.risk}
      </text>
      <text fg="#cbd5e1">{props.request.metadata.reason}</text>
      <text fg="#94a3b8">{props.request.metadata.command_preview}</text>
      <text fg="#64748b">
        y once | a always | n reject | f reject+feedback
      </text>
    </box>
  )
}

