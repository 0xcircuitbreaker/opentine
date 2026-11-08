/**
 * verify-browser: the Web Worker entry point that turns a run's verification
 * record into the badge the viewer shows. It runs off the main thread so a
 * large run never blocks rendering, and it makes no network request.
 *
 * Honesty rule: the browser itself has not re-run the cryptographic checks yet
 * (the bundled TS verifier lands with the opentine-web M1 browser build), so a
 * state computed by local `tine` is passed through labelled as such, and the
 * browser's own column always reads "unchecked".
 */
const STATES = ["verified", "failed", "partial", "unchecked", "unpinned"];
export function asState(value) {
    return STATES.includes(value) ? value : "unchecked";
}
export function badge(v) {
    const by = v.computed_by || "local tine";
    const rows = [
        ["Integrity digest", asState(v.integrity), by],
        ["Signature", asState(v.signature), by],
        ["Browser re-check", "unchecked", "this browser (verifier bundle not loaded)"],
    ];
    const state = asState(v.overall);
    const tier = v.assurance ? ` · assurance ${v.assurance.verified} (claimed ${v.assurance.claimed})` : "";
    return { state, label: `${state} by ${by}${tier}`, rows };
}
const scope = globalThis;
if (scope.document === undefined && typeof scope.postMessage === "function") {
    scope.onmessage = (event) => scope.postMessage(badge(event.data || {}));
}
