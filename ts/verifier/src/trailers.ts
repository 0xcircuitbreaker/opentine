/**
 * The 0.45 commit trailer grammar, parsed exactly as opentine/_trailers.py does:
 *
 *   Tine-Run: <run-oid>[ <project_id>]     (repeatable)
 *   Tine-Project: <project_id>             (at most once)
 *
 * Lines end at "\n" only (one trailing "\r" is dropped), keys are ASCII and
 * matched without case, and words split on spaces and tabs only. Vectors:
 * tests/data/trailer_vectors.json.
 */

export const MAX_RUNS_PER_COMMIT = 50;
const RUN_ID = /^(?:run:sha256:[0-9a-f]{64}|[A-Za-z0-9][A-Za-z0-9._:-]{3,199})$/;
const OID = /^run:sha256:[0-9a-f]{64}$/;
const PROJECT_ID = /^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/;
const ASCII = /^[\x00-\x7f]*$/;

export interface Link {
  run: string;
  project: string;
}

export class TrailerError extends Error {}

function project(value: string): string {
  if (!PROJECT_ID.test(value)) throw new TrailerError(`malformed project id: ${JSON.stringify(value.slice(0, 80))}`);
  return value;
}

function run(value: string): string {
  const oidLike = value.slice(0, 4).toLowerCase() === "run:";
  if (!RUN_ID.test(value) || (oidLike && !OID.test(value))) {
    throw new TrailerError(`malformed run id: ${JSON.stringify(value.slice(0, 80))}`);
  }
  return value;
}

/** The link set a commit message names; throws TrailerError on bad grammar. */
export function parseTrailers(message: string): Link[] {
  const runs: Array<[string, string]> = [];
  let shared = "";
  let seenProject = false;
  for (const raw of message.split("\n")) {
    const line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
    const colon = line.indexOf(":");
    if (colon < 0) continue;
    const key = line.slice(0, colon);
    if (!ASCII.test(key)) continue;
    const lower = key.toLowerCase();
    if (lower !== "tine-run" && lower !== "tine-project") continue;
    const words = line.slice(colon + 1).split(/[ \t]+/).filter((word) => word !== "");
    if (lower === "tine-project") {
      if (seenProject) throw new TrailerError("Tine-Project may appear at most once");
      if (words.length !== 1) throw new TrailerError("Tine-Project takes exactly one project id");
      shared = project(words[0]);
      seenProject = true;
      continue;
    }
    if (words.length < 1 || words.length > 2) {
      throw new TrailerError("Tine-Run takes a run id and an optional project id");
    }
    runs.push([run(words[0]), words.length === 2 ? project(words[1]) : ""]);
  }
  const seen = new Set<string>();
  const links: Link[] = [];
  for (const [id, own] of runs) {
    const link = { run: id, project: own || shared };
    const key = `${link.run}\n${link.project}`;
    if (seen.has(key)) continue;
    seen.add(key);
    links.push(link);
  }
  return links.slice(0, MAX_RUNS_PER_COMMIT);
}
