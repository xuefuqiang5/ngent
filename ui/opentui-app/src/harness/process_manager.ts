export function coreDevCommand(): string[] {
  return ["cargo", "run", "-q", "-p", "netagent-core"]
}
