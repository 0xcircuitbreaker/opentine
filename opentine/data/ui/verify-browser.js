/**
 * verify-browser: the Web Worker entry point that turns a run's verification
 * record into the badge the viewer shows. It runs off the main thread so a
 * large run never blocks rendering, and it fetches only the run's own artifact
 * bytes, from the page's origin.
 *
 * Two columns, each named for who computed it: the states local `tine`
 * computed (passed through, labelled "local tine"), and the states this
 * browser computed itself by running the bundled TS verifier
 * (`tine-verifier.js`) over the artifact bytes: integrity (every envelope id,
 * the root and the annotation chain) and the `tine-sig/3` signatures. No key is
 * pinned in a browser, so a signature that holds under the key the file embeds
 * reads "unpinned", never "verified"; an HMAC signature reads "unchecked". When
 * the bytes are withheld (the server's redaction scan found something) or the
 * check cannot run, the browser column reads "unchecked" and says why.
 *
 * 0.51: a file the viewer is handed (`{file: Blob}`) is checked here too, read
 * with `Blob.slice` and never uploaded: a `tine bundle` file (streamed, no
 * whole-file buffer), a `.tine` v4/v5 artifact, or one signed record. Every
 * check reads pass, fail, or unchecked with its reason; a check this browser
 * did not run is never listed as passed.
 */
import { blobSource, isBundle, OPENTINE_VERSION, recordKinds, verifyArtifact, verifyBundle, verifyRecordBytes, } from "./tine-verifier.js";
const STATES = ["verified", "failed", "partial", "unchecked", "unpinned"];
const HERE = "this browser (TS verifier)";
export function asState(value) {
    return STATES.includes(value) ? value : "unchecked";
}
/** The browser column for a TS verifier report, or for a check that could not run. */
export function browserStates(report, why = "") {
    if (!report)
        return { integrity: "unchecked", signature: "unchecked", detail: why || "not checked" };
    const integrity = report.integrity.ok ? "verified" : "failed";
    const sig = report.signature;
    let signature = "unchecked";
    let detail = report.integrity.reason;
    if (sig && (sig.state === "mismatch" || sig.state === "error"))
        signature = "failed";
    else if (sig && sig.state === "verified")
        signature = "verified";
    else if (sig && sig.state === "verified-tofu")
        signature = "unpinned";
    if (sig)
        detail = `${detail}; signature ${sig.state}: ${sig.reason}`;
    return { integrity, signature, detail };
}
export function badge(v, check) {
    const by = v.computed_by || "local tine";
    const mine = check ?? browserStates(null, "verifier not run");
    const rows = [
        ["Integrity digest", asState(v.integrity), by],
        ["Signature", asState(v.signature), by],
        ["Integrity (re-checked)", mine.integrity, HERE],
        ["Signature (re-checked)", mine.signature, HERE],
    ];
    const failed = mine.integrity === "failed" || mine.signature === "failed";
    const state = failed ? "failed" : asState(v.overall);
    const tier = v.assurance ? ` · assurance ${v.assurance.verified} (claimed ${v.assurance.claimed})` : "";
    const again = mine.integrity === "unchecked" ? "not re-checked in this browser" : `re-checked in this browser: integrity ${mine.integrity}, signature ${mine.signature}`;
    return { state, label: `${state} by ${by}${tier}; ${again}`, rows, detail: mine.detail };
}
/** Fetch the artifact bytes and check them here; never throws. */
export async function check(request) {
    if (!request.artifact)
        return browserStates(null, "no artifact to check");
    try {
        const res = await fetch(request.artifact, { credentials: "same-origin" });
        if (!res.ok) {
            const why = res.status === 403 ? "artifact withheld: the redaction scan found something" : `artifact unavailable (${res.status})`;
            return browserStates(null, why);
        }
        return browserStates(await verifyArtifact(new Uint8Array(await res.arrayBuffer()), "artifact"));
    }
    catch (exc) {
        return browserStates(null, `check could not run: ${exc.message}`);
    }
}
const scope = globalThis;
if (scope.document === undefined && typeof scope.postMessage === "function") {
    scope.onmessage = (event) => {
        const file = event.data?.file;
        if (file) {
            void checkFile(file).then((report) => scope.postMessage(report));
            return;
        }
        const data = (event.data || {});
        const request = data.verification ? data : { verification: data };
        void check(request).then((mine) => scope.postMessage(badge(request.verification, mine)));
    };
}
const MAX_SMALL_FILE = 256 * 1024 * 1024;
/** The canon rows of an artifact report: unsigned or unpinned is never "pass" by omission. */
const PINNED = ["Signer identity (pinned key)", "unchecked", "no key is pinned in a browser"];
export function artifactRows(report) {
    const rows = [
        ["Integrity (envelope ids, root, annotation chain)", report.integrity.ok ? "pass" : "fail", report.integrity.reason],
    ];
    const sig = report.signature;
    if (!sig || sig.state === "unsigned")
        rows.push(["Signature", "unchecked", "the artifact carries no signature"]);
    else if (sig.state === "no-key")
        rows.push(["Signature", "unchecked", "an HMAC signature needs the signer's key"]);
    else if (sig.state === "mismatch" || sig.state === "error")
        rows.push(["Signature", "fail", sig.reason]);
    else if (sig.state === "verified-tofu")
        rows.push(["Signature", "pass", "holds under the key the file embeds (unpinned)"]);
    else
        rows.push(["Signature", "pass", sig.reason]);
    rows.push(PINNED);
    return rows;
}
export function bundleRows(report) {
    const rows = report.checks.map((item) => [item.name, item.state, item.reason]);
    if (report.ok && !report.transparency)
        rows.push(["transparency receipts", "unchecked", "none carried"]);
    if (report.ok && (report.signatures || report.redacted_public))
        rows.push(PINNED);
    return rows;
}
function recordRows(found) {
    const rows = [[found.kind ? `record ${found.kind}` : "record", found.state, found.reason]];
    if (found.state === "pass")
        rows.push(PINNED);
    return rows;
}
/** Check a file in this browser; never throws, never makes a request. */
export async function checkFile(file) {
    const built_for = OPENTINE_VERSION;
    try {
        const head = new Uint8Array(await file.slice(0, 16).arrayBuffer());
        if (isBundle(head)) {
            const report = await verifyBundle(blobSource(file));
            const refs = Object.keys(report.refs).length;
            const summary = report.ok ? `bundle ${report.bundle}: ${report.objects} objects, ${refs} refs` : `bundle refused: ${report.reason}`;
            return { kind: "bundle", verdict: report.verdict, summary, rows: bundleRows(report), built_for };
        }
        if (file.size > MAX_SMALL_FILE)
            throw new Error("file exceeds the 256 MiB artifact limit");
        const raw = new Uint8Array(await file.arrayBuffer());
        if (raw[0] === 0x7b) {
            const found = verifyRecordBytes(raw);
            if (recordKinds().includes(found.kind)) {
                const verdict = found.state === "fail" ? "fail" : "pass";
                return { kind: "record", verdict, summary: `${found.kind}: ${found.state}`, rows: recordRows(found), built_for };
            }
        }
        const report = await verifyArtifact(raw, "artifact");
        const summary = `artifact ${report.format ?? "?"}, root ${report.root ?? "-"}`;
        return { kind: "artifact", verdict: report.ok ? "pass" : "fail", summary, rows: artifactRows(report), built_for };
    }
    catch (exc) {
        return { kind: "unknown", verdict: "fail", summary: "check could not run", rows: [["file", "unchecked", exc.message]], built_for };
    }
}
