import type { DashboardSnapshot, SessionState, SyncState, ViewMode } from "../app/state"

export function StatusBar(props: {
  title: string
  mode: ViewMode
  sync: SyncState
  session: SessionState
  snapshot: DashboardSnapshot
  pendingCount: number
}) {
  return (
    <box
      flexDirection="row"
      justifyContent="space-between"
      borderStyle="single"
      borderColor="#334155"
      paddingX={1}
      paddingY={0}
    >
      <text fg="#e2e8f0">{props.title}</text>
      <text fg="#94a3b8">
        mode={props.mode} sync={props.sync.status} session={props.session.status} pending=
        {props.pendingCount} iface={props.snapshot.interfaces.join(",") || "n/a"}
      </text>
    </box>
  )
}
