export class HarnessNotImplementedError extends Error {
  constructor(message = "Harness is not implemented in Phase 0.") {
    super(message)
    this.name = "HarnessNotImplementedError"
  }
}

