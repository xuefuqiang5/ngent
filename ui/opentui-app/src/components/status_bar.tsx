import type {
  CaptureState,
  DashboardSnapshot,
  SessionState,
  SyncState,
  ViewMode,
} from "../app/state"

export function StatusBar(props: {
  mode: ViewMode
  sync: SyncState
  session: SessionState
  snapshot: DashboardSnapshot
  capture: CaptureState
  pendingCount: number
}) {
  const iface =
    props.capture.captureInterface !== "n/a"
      ? props.capture.captureInterface
      : props.snapshot.interfaces[0] ?? "n/a"
  const coreStatus = props.sync.status === "error" ? "error" : props.sync.status

  return (
    <box
      flexDirection="row"
      justifyContent="space-between"
      paddingX={1}
      paddingY={0}
    >
      <text fg="#e5e7eb">NetAgent</text>
      <text fg="#94a3b8">
        {coreStatus} · mode:{props.mode} · session:{props.session.status} · capture:
        {props.capture.status} · iface:{iface} · pending:{props.pendingCount}
      </text>
    </box>
  )
}
