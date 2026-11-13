/**
 * run-viewer: the shared OpenTine run viewer. `tine ui` serves it next to a
 * redacted JSON API on 127.0.0.1; opentine-web embeds the same module.
 *
 * Rules: every recorded value is inserted with textContent, never parsed as markup,
 * all data comes from the page's own origin, and the timeline renders rows
 * lazily in fixed-size chunks so a 10k-step run stays interactive.
 *
 * 0.51: "Verify a file" checks a bundle, a .tine artifact or a signed record
 * the user picks, in a Web Worker, without uploading it anywhere.
 */

import type { Badge, FileReport, Verification } from "./verify-browser.js";

type J = Record<string, unknown>;
interface Summary { id: string; status: string; model: string; steps: number; parents: string[]; forked_from: string; fleet: J | null }
interface Row { index: number; kind: string; model: string; tool: string; parents: number; error: boolean }
interface StepDoc { id: string; parent_ids: string[]; input_parts: unknown; inputs: unknown; outputs: unknown; error: J }
interface RunDoc extends Summary { user_prompt: string; system_prompt: string; timeline: Row[] }

export const CHUNK = 500;
const TABS = ["Timeline", "Workspace", "Run DAG", "Fleet", "Verify", "Attribution"];

function el<K extends keyof HTMLElementTagNameMap>(tag: K, text?: string, cls?: string): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (cls) node.className = cls;
  return node;
}

function pretty(value: unknown): string {
  return typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(path, { credentials: "same-origin" });
  if (!res.ok) throw new Error(`${path}: ${res.status}`);
  return (await res.json()) as T;
}

function details(label: string, value: unknown): HTMLElement | null {
  if (value === null || value === undefined || value === "" || (typeof value === "object" && Object.keys(value as object).length === 0)) return null;
  const d = el("details");
  d.append(el("summary", label), el("pre", pretty(value)));
  return d;
}

function stepRow(runId: string, step: Row): HTMLLIElement {
  const li = el("li", undefined, `step kind-${step.kind}`);
  li.id = `step-${step.index}`;
  li.tabIndex = -1;
  const head = el("div", undefined, "meta");
  head.append(el("span", `#${step.index}`), el("b", ` ${step.kind}`));
  for (const part of [step.model, step.tool].filter(Boolean)) head.append(el("span", ` · ${part}`));
  if (step.error) head.append(el("span", " error", "err"));
  const body = el("details");
  body.append(el("summary", "Details"));
  body.addEventListener("toggle", () => {
    if (!body.open || body.dataset.loaded) return;
    body.dataset.loaded = "1";
    void get<StepDoc>(`/api/run/${encodeURIComponent(runId)}/step/${step.index}`).then((doc) => {
      body.append(el("p", `step ${doc.id}${doc.parent_ids.length > 1 ? ` · merges ${doc.parent_ids.length} parents` : ""}`, "meta"));
      for (const [label, value] of [["Input parts", doc.input_parts], ["Inputs / tool args", doc.inputs], ["Outputs / tool result", doc.outputs], ["Error", doc.error]] as [string, unknown][]) {
        const block = details(label, value);
        if (block) body.append(block);
      }
    });
  });
  li.append(head, body);
  return li;
}

export function renderTimeline(host: HTMLElement, runId: string, steps: Row[]): void {
  const list = el("ol", undefined, "timeline");
  list.setAttribute("aria-label", "Run timeline");
  let shown = 0;
  const more = el("button", "", "more");
  const grow = () => {
    const frag = document.createDocumentFragment();
    for (const step of steps.slice(shown, shown + CHUNK)) frag.append(stepRow(runId, step));
    list.append(frag);
    shown = Math.min(steps.length, shown + CHUNK);
    more.textContent = `Show more (${shown} of ${steps.length})`;
    more.hidden = shown >= steps.length;
  };
  more.addEventListener("click", grow);
  list.addEventListener("keydown", (ev) => {
    const at = (document.activeElement as HTMLElement | null)?.closest("li.step") as HTMLElement | null;
    const next = ev.key === "j" || ev.key === "ArrowDown" ? at?.nextElementSibling : ev.key === "k" || ev.key === "ArrowUp" ? at?.previousElementSibling : null;
    if (next instanceof HTMLElement) { ev.preventDefault(); next.focus(); }
  });
  grow();
  host.replaceChildren(list, more);
  (list.firstElementChild as HTMLElement | null)?.setAttribute("tabindex", "0");
}

async function renderWorkspace(host: HTMLElement, run: RunDoc): Promise<void> {
  const last = Math.max(0, run.timeline.length - 1);
  const form = el("div", undefined, "controls");
  const step = el("input");
  step.type = "number"; step.min = "0"; step.max = String(last); step.value = String(last);
  step.setAttribute("aria-label", "Workspace at step");
  const base = el("input");
  base.type = "number"; base.min = "0"; base.max = String(last); base.value = "0";
  base.setAttribute("aria-label", "Diff from step");
  const go = el("button", "Show");
  const out = el("div");
  form.append(el("label", "Tree at step "), step, el("label", " diff from step "), base, go);
  const show = async () => {
    const id = encodeURIComponent(run.id);
    const tree = await get<Record<string, string | null>>(`/api/run/${id}/tree?step=${step.value}`);
    const diff = await get<Record<string, string>>(`/api/run/${id}/diff?a=${base.value}&b=${step.value}`);
    const files = el("ul", undefined, "tree");
    for (const [path, body] of Object.entries(tree)) files.append(el("li", body === null ? `${path} (content not recorded)` : path));
    out.replaceChildren(el("h3", "Files"), Object.keys(tree).length ? files : el("p", "No recorded file writes."), el("h3", "Diff"));
    for (const [path, text] of Object.entries(diff)) { const d = details(path, text); if (d) out.append(d); }
  };
  go.addEventListener("click", () => void show());
  host.replaceChildren(form, out);
  await show();
}

function renderDag(host: HTMLElement, run: RunDoc, runs: Summary[]): void {
  const ul = el("ul", undefined, "dag");
  const parents = [...run.parents, ...(run.forked_from ? [run.forked_from] : [])];
  for (const p of parents) ul.append(el("li", `parent ${p}`));
  ul.append(el("li", `this run ${run.id}`, "self"));
  for (const r of runs) if (r.parents.includes(run.id) || r.forked_from === run.id) ul.append(el("li", `child ${r.id}`));
  const steps = el("p", `${run.timeline.filter((s) => s.parents > 1).length} merge steps; ${run.timeline.length} steps in all.`);
  host.replaceChildren(ul, steps);
}

function renderFleet(host: HTMLElement, runs: Summary[]): void {
  const groups = new Map<string, Summary[]>();
  for (const r of runs) {
    const key = r.fleet && typeof r.fleet.id === "string" ? r.fleet.id : "";
    if (key) groups.set(key, [...(groups.get(key) || []), r]);
  }
  if (!groups.size) { host.replaceChildren(el("p", "No fleet records among these runs.")); return; }
  const ul = el("ul", undefined, "fleet");
  for (const [id, members] of groups) ul.append(el("li", `fleet ${id}: ${members.map((m) => m.id.slice(0, 12)).join(", ")}`));
  host.replaceChildren(ul);
}

async function renderVerify(host: HTMLElement, runId: string): Promise<void> {
  const box = el("div", "Checking…");
  box.setAttribute("aria-live", "polite");
  host.replaceChildren(box);
  const v = await get<Verification>(`/api/run/${encodeURIComponent(runId)}/verify`);
  const worker = new Worker("verify-browser.js", { type: "module" });
  worker.onmessage = (ev: MessageEvent<Badge>) => {
    const b = ev.data;
    const table = el("table");
    for (const [what, state, by] of b.rows) {
      const tr = el("tr");
      tr.append(el("td", what), el("td", state, `state ${state}`), el("td", by));
      table.append(tr);
    }
    box.replaceChildren(el("p", b.label, `state ${b.state}`), table);
    for (const r of v.reasons || []) box.append(el("p", r, "meta"));
    box.append(el("p", `this browser: ${b.detail}`, "meta"));
    worker.terminate();
  };
  worker.postMessage({ verification: v, artifact: `/api/run/${encodeURIComponent(runId)}/artifact` });
}

async function renderAttribution(host: HTMLElement, runId: string): Promise<void> {
  const rows = await get<{ path: string; step: number; model: string }[]>(`/api/run/${encodeURIComponent(runId)}/attribution`);
  if (!rows.length) { host.replaceChildren(el("p", "No recorded file writes.")); return; }
  const table = el("table");
  for (const row of rows) {
    const tr = el("tr");
    tr.append(el("td", row.path), el("td", `step ${row.step}`), el("td", row.model || "-"));
    table.append(tr);
  }
  host.replaceChildren(table);
}

async function openRun(main: HTMLElement, id: string, runs: Summary[]): Promise<void> {
  const run = await get<RunDoc>(`/api/run/${encodeURIComponent(id)}`);
  const header = el("header");
  header.append(el("h2", `Run ${run.id}`), el("p", `${run.status} · ${run.model || "-"} · ${run.timeline.length} steps`, "meta"));
  if (run.user_prompt) header.append(details("Prompt", run.user_prompt) as HTMLElement);
  const tabs = el("div", undefined, "tabs");
  tabs.setAttribute("role", "tablist");
  const panel = el("section");
  panel.setAttribute("role", "tabpanel");
  const buttons = TABS.map((name, i) => {
    const b = el("button", name);
    b.setAttribute("role", "tab");
    b.addEventListener("click", () => void select(i));
    b.addEventListener("keydown", (ev) => {
      const d = ev.key === "ArrowRight" ? 1 : ev.key === "ArrowLeft" ? -1 : 0;
      if (d) { const n = (i + d + TABS.length) % TABS.length; buttons[n].focus(); void select(n); }
    });
    return b;
  });
  tabs.append(...buttons);
  const select = async (i: number) => {
    buttons.forEach((b, j) => { b.setAttribute("aria-selected", String(i === j)); b.tabIndex = i === j ? 0 : -1; });
    if (i === 0) renderTimeline(panel, run.id, run.timeline);
    else if (i === 1) await renderWorkspace(panel, run);
    else if (i === 2) renderDag(panel, run, runs);
    else if (i === 3) renderFleet(panel, runs);
    else if (i === 4) await renderVerify(panel, run.id);
    else await renderAttribution(panel, run.id);
  };
  main.replaceChildren(header, tabs, panel);
  await select(0);
}

/** Render a worker's file report: one row per check, each pass / fail / unchecked with its reason. */
export function renderFileReport(host: HTMLElement, report: FileReport): void {
  const table = el("table");
  table.setAttribute("aria-label", "Checks run in this browser");
  for (const [what, state, why] of report.rows) {
    const tr = el("tr");
    tr.dataset.state = state;
    const css = state === "pass" ? "verified" : state === "fail" ? "failed" : "unchecked";
    tr.append(el("td", what), el("td", state, `state ${css}`), el("td", why));
    table.append(tr);
  }
  const head = el("p", `${report.verdict}: ${report.summary}`, `state ${report.verdict === "pass" ? "verified" : "failed"}`);
  head.id = "file-verdict";
  head.dataset.verdict = report.verdict;
  host.replaceChildren(head, table, el("p", `checked in this browser by the verifier built for OpenTine ${report.built_for}; nothing was uploaded`, "meta"));
}

function fileVerifier(main: HTMLElement): HTMLElement {
  const box = el("div", undefined, "controls");
  const label = el("label", "Verify a file (bundle, .tine, record) ");
  const input = el("input");
  input.type = "file";
  input.id = "verify-file";
  label.append(input);
  input.addEventListener("change", () => {
    const file = input.files?.[0];
    if (!file) return;
    const out = el("div", "Checking…");
    out.setAttribute("aria-live", "polite");
    main.replaceChildren(el("h2", `File ${file.name}`), out);
    const worker = new Worker("verify-browser.js", { type: "module" });
    worker.onmessage = (ev: MessageEvent<FileReport>) => {
      renderFileReport(out, ev.data);
      worker.terminate();
    };
    worker.postMessage({ file });
  });
  box.append(label);
  return box;
}

export async function start(): Promise<void> {
  const nav = document.getElementById("runs") as HTMLElement;
  const main = document.getElementById("main") as HTMLElement;
  let runs: Summary[] = [];
  try {
    runs = await get<Summary[]>("/api/runs");
  } catch {
    nav.replaceChildren(el("p", "No run API here."), fileVerifier(main));
    return;
  }
  const ul = el("ul");
  for (const r of runs) {
    const b = el("button", `${r.id.slice(0, 12)} · ${r.status} · ${r.steps} steps`);
    b.addEventListener("click", () => void openRun(main, r.id, runs));
    const li = el("li");
    li.append(b);
    ul.append(li);
  }
  nav.replaceChildren(runs.length ? ul : el("p", "No runs found."), fileVerifier(main));
  if (runs.length === 1) await openRun(main, runs[0].id, runs);
}

if (typeof document !== "undefined") void start();
