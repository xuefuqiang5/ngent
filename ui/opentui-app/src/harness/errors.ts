export class HarnessNotImplementedError extends Error {
  constructor(message = "The requested Harness capability is not available.") {
    super(message)
    this.name = "HarnessNotImplementedError"
  }
}
