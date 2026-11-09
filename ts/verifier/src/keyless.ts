/**
 * SPEC 8.12.1 (0.48): an RFC 3161 token bound to a Rekor v2 keyless signature.
 * A port of `opentine._keyless_tsa.bind_request`. Tokens arrive decoded; their CMS
 * signature and chain (SPEC 8.6) are not checked here. What is checked is the
 * binding: the imprint covers the DSSE signature bytes, genTime sits inside the
 * TSA's validFor and (with its accuracy) inside the leaf certificate's validity,
 * and the earliest genTime is the verified signing time. Every refusal carries a
 * `keyless.*` code.
 */

import { createHash, timingSafeEqual } from "node:crypto";

import { TineError } from "./errors.js";
import { isInt, isObject, type JObject, type JValue } from "./json.js";
import { strictBase64 } from "./pack.js";
import { parseTime } from "./delegation.js";

const HASHES = ["sha256", "sha384", "sha512"];
const MAX_TOKENS = 16;

function fail(code: string, message: string): never {
  const prefix = code === "malformed" ? "keyless input is malformed: " : "";
  throw new TineError(prefix + message, `keyless.${code}`);
}

/** Microseconds since the epoch, as Python's datetime keeps them (Date only has ms). */
function time(value: JValue | undefined, what: string): bigint {
  let ms: number;
  try {
    ms = parseTime(value, what);
  } catch {
    return fail("malformed", `${what} is not an RFC 3339 time with a zone`);
  }
  const fraction = /:\d{2}\.(\d{1,6})/.exec(value as string);
  const micros = fraction ? BigInt(fraction[1].padEnd(6, "0").slice(3)) : 0n;
  return BigInt(Math.floor(ms)) * 1000n + micros;
}

function window(value: JValue | undefined, what: string): [bigint, bigint | null] {
  if (!isObject(value) || !value.has("start") || [...value.keys()].some((key) => key !== "start" && key !== "end")) {
    fail("malformed", `${what} must be {start, end?}`);
  }
  const end = (value as JObject).get("end");
  return [time((value as JObject).get("start"), `${what}.start`), end ? time(end, `${what}.end`) : null];
}

function stamp(us: bigint): string {
  const micros = ((us % 1000000n) + 1000000n) % 1000000n;
  const text = new Date(Number((us - micros) / 1000n)).toISOString().slice(0, 19);
  return micros ? `${text}.${String(micros).padStart(6, "0")}Z` : `${text}Z`;
}

export function keylessSigningTime(input: JValue): { signing_time: string | null; status: string } {
  if (!isObject(input)) fail("malformed", "the request is not an object");
  const value = input as JObject;
  let signature: Uint8Array;
  try {
    signature = strictBase64(value.get("signature"));
  } catch {
    return fail("malformed", "signature is not base64");
  }
  const receipt = value.get("receipt");
  if (receipt !== "verified") fail("receipt-invalid", `the Rekor v2 receipt is ${String(receipt)}, not verified`);
  const tokens = value.get("tokens");
  if (!Array.isArray(tokens) || tokens.length > MAX_TOKENS) fail("malformed", `tokens must be a list of at most ${MAX_TOKENS}`);
  const [start, end] = window(value.get("leaf"), "leaf");
  if (!tokens.length) return { signing_time: null, status: "unchecked" };
  const times: bigint[] = [];
  (tokens as JValue[]).forEach((item, index) => {
    if (!isObject(item) || !HASHES.includes(item.get("hash_algorithm") as string)) {
      fail("malformed", `token ${index}: hash_algorithm is one of sha256, sha384, sha512`);
    }
    const token = item as JObject;
    const raw = token.get("message_imprint");
    if (typeof raw !== "string" || !/^([0-9a-fA-F]{2})*$/.test(raw)) fail("malformed", `token ${index}: message_imprint is not hex`);
    const imprint = Buffer.from(raw as string, "hex");
    const expected = createHash(token.get("hash_algorithm") as string).update(signature).digest();
    if (imprint.length !== expected.length || !timingSafeEqual(imprint, expected)) {
      fail("tsa-imprint-mismatch", `token ${index} does not cover the signature`);
    }
    const gen = time(token.get("gen_time"), `token ${index} gen_time`);
    const accuracy = token.get("accuracy_us") ?? 0n;
    if (!isInt(accuracy) || accuracy < 0n) fail("malformed", `token ${index}: accuracy_us is a non-negative integer`);
    const tsa = token.get("tsa_valid_for");
    if (tsa !== undefined && tsa !== null) {
      const [tsaStart, tsaEnd] = window(tsa, `token ${index} tsa_valid_for`);
      if (gen < tsaStart || (tsaEnd !== null && gen > tsaEnd)) fail("tsa-retired", `token ${index}: genTime is outside its TSA's validFor`);
    }
    const slack = accuracy as bigint;
    if (!(start <= gen - slack && (end === null || gen + slack <= end))) {
      fail("cert-not-valid-at-signing", `token ${index}: the certificate was not valid at genTime ${stamp(gen)}`);
    }
    times.push(gen);
  });
  return { signing_time: stamp(times.reduce((a, b) => (b < a ? b : a))), status: "verified" };
}
