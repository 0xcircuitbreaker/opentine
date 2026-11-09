/**
 * SPEC 4.19 `opentine.prompt` (a signed, hash-chained prompt version) and SPEC
 * 4.20 `opentine.memory` (a signed team-memory note), 0.47. A port of
 * `opentine._prompt.check` and `opentine._memory.check`: exactly each kind's
 * fields, then a `tine-sig/3` Ed25519 block over the kind's domain prefix + JCS
 * of `{"body", "header"}` (under the pinned key or, without one, the embedded
 * key: trust on first use). Refusals carry `prompt.*` and `memory.*` codes.
 */

import { TineError } from "./errors.js";
import { isObject, type JObject, type JValue } from "./json.js";
import { projectDigest, signedBy } from "./project.js";

const PROMPT_FIELDS = ["kind", "prompt_version", "name", "version", "prev", "template", "variables", "model", "created_at"];
const MEMORY_FIELDS = ["kind", "memory_version", "scope", "topic", "text", "tags", "subject", "supersedes", "author", "created_at"];
const ID = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const TAG = /^[a-z0-9][a-z0-9._:-]{0,63}$/;
const NAME = /^[A-Za-z0-9_.:/@+-]{1,256}$/;
const WHEN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;
const BLOB = /^blob:sha256:[0-9a-f]{64}$/;
const RUN = /^run:sha256:[0-9a-f]{64}$/;
const HOLE = /\{\{([A-Za-z_][A-Za-z0-9_]{0,63})\}\}/g;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\x00-\x08\x0b-\x1f\x7f]/;
const BLANK = /^[ \t\n]*$/;
const encoder = new TextEncoder();

function refuse(code: string, message: string): never {
  throw new TineError(message, code);
}

function int(value: JValue | undefined): number | null {
  if (typeof value === "bigint") return value > -(2n ** 53n) && value < 2n ** 53n ? Number(value) : null;
  if (typeof value === "number" && Number.isInteger(value)) return value;
  return null;
}

function is(value: JValue | undefined, pattern: RegExp): value is string {
  return typeof value === "string" && pattern.test(value);
}

function fields(record: JValue, kind: string, names: string[], code: string, subject: string): JObject {
  if (!isObject(record) || record.get("kind") !== kind) refuse(`${code}.malformed`, `${subject} is malformed: kind is not ${kind}`);
  const object = record as JObject;
  const keys = [...object.keys()];
  if (keys.some((key) => key !== "signature" && !names.includes(key)) || names.some((key) => !object.has(key))) {
    refuse(`${code}.malformed`, `${subject} is malformed: wrong set of fields`);
  }
  return new Map(names.map((name) => [name, object.get(name) as JValue]));
}

function sortedDistinct(values: string[]): string[] {
  return [...new Set(values)].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

function sameList(left: JValue | undefined, right: string[]): boolean {
  return Array.isArray(left) && left.length === right.length && left.every((item, index) => item === right[index]);
}

function promptBody(record: JValue): JObject {
  const found = fields(record, "opentine.prompt", PROMPT_FIELDS, "prompt", "prompt version");
  const version = int(found.get("version"));
  const prev = found.get("prev");
  const template = found.get("template");
  const variables = found.get("variables");
  const model = found.get("model");
  const checks: [boolean, string][] = [
    [int(found.get("prompt_version")) === 1, "prompt_version"],
    [is(found.get("name"), ID), "name"],
    [version !== null && version >= 1 && version <= 2 ** 31 - 1, "version counts from 1"],
    [(version === 1) === (prev === null) && (prev === null || is(prev, BLOB)), "prev"],
    [typeof template === "string" && template !== "" && !template.includes("\u0000") && encoder.encode(template).length <= 65_536, "template"],
    [Array.isArray(variables) && variables.every((item) => typeof item === "string"), "variables"],
    [model === null || is(model, NAME), "model"],
    [is(found.get("created_at"), WHEN), "created_at must be an RFC 3339 UTC time"],
  ];
  for (const [ok, message] of checks) if (!ok) refuse("prompt.malformed", `prompt version is malformed: ${message}`);
  const holes = sortedDistinct([...(template as string).matchAll(HOLE)].map((match) => match[1]));
  if (!sameList(variables, holes)) refuse("prompt.variables-mismatch", "the variables are not the template's placeholders");
  return found;
}

/** Verify one prompt version, after `previous` when given, under `publicKey` or its embedded key. */
export function verifyPrompt(record: JValue, previous: JValue | null = null, publicKey: Uint8Array | null = null): Record<string, unknown> {
  const found = promptBody(record);
  const signer = signedBy(record, found, "opentine.prompt.v1:", "prompt", "prompt version", publicKey);
  if (previous !== null) {
    const prior = promptBody(previous);
    const next = (int(prior.get("version")) as number) + 1;
    if (found.get("prev") !== projectDigest(previous) || int(found.get("version")) !== next || found.get("name") !== prior.get("name")) {
      refuse("prompt.chain-break", "the version does not follow its predecessor");
    }
    const block = (previous as JObject).get("signature");
    if (!isObject(block) || block.get("public_key") !== signer) refuse("prompt.wrong-signer", "not signed by its predecessor's key");
  }
  return {
    name: found.get("name"),
    version: int(found.get("version")),
    digest: projectDigest(record),
    signer,
    variables: [...(found.get("variables") as string[])],
    state: publicKey !== null ? "verified" : "verified-tofu",
  };
}

/** Verify one memory note under `publicKey`, a `team` of hex keys, or its embedded key. */
export function verifyMemory(record: JValue, publicKey: Uint8Array | null = null, team: JValue = []): Record<string, unknown> {
  const found = fields(record, "opentine.memory", MEMORY_FIELDS, "memory", "memory note");
  const text = found.get("text");
  const tags = found.get("tags");
  const subject = found.get("subject") ?? null;
  const supersedes = found.get("supersedes") ?? null;
  const checks: [boolean, string][] = [
    [int(found.get("memory_version")) === 1, "memory_version"],
    [is(found.get("scope"), ID) && is(found.get("topic"), ID), "scope and topic"],
    [typeof text === "string" && !BLANK.test(text) && encoder.encode(text).length <= 8192 && !CONTROL.test(text), "text"],
    [Array.isArray(tags) && tags.length <= 32 && tags.every((tag) => is(tag, TAG)) && sameList(tags, sortedDistinct(tags as string[])), "tags"],
    [subject === null || is(subject, RUN) || is(subject, BLOB), "subject"],
    [supersedes === null || is(supersedes, BLOB), "supersedes"],
    [is(found.get("author"), NAME), "author"],
    [is(found.get("created_at"), WHEN), "created_at must be an RFC 3339 UTC time"],
  ];
  for (const [ok, message] of checks) if (!ok) refuse("memory.malformed", `memory note is malformed: ${message}`);
  const signer = signedBy(record, found, "opentine.memory.v1:", "memory", "memory note", publicKey);
  const members = new Set(Array.isArray(team) ? team.filter((key): key is string => typeof key === "string") : []);
  if (members.size > 0 && !members.has(signer)) refuse("memory.untrusted-signer", "the memory note's signer is not on the team");
  return {
    scope: found.get("scope"),
    topic: found.get("topic"),
    digest: projectDigest(record),
    signer,
    subject,
    supersedes,
    tags: [...(tags as string[])],
    state: publicKey !== null || members.size > 0 ? "verified" : "verified-tofu",
  };
}
