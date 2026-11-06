/**
 * A refusal. `code` is this package's own identifier; the conformance adapter
 * maps it onto a REASON_CODES.md code per operation.
 */
export class TineError extends Error {
  constructor(
    message: string,
    readonly code: string = "error",
  ) {
    super(message);
    this.name = "TineError";
  }
}
