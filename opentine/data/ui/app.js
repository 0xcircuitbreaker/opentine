/**
 * run-viewer: the shared OpenTine run viewer. `tine ui` serves it next to a
 * redacted JSON API on 127.0.0.1; opentine-web embeds the same module.
 *
 * Rules: every recorded value is inserted with textContent, never parsed as markup,
 * all data comes from the page's own origin, and the timeline renders rows
 * lazily in fixed-size chunks so a 10k-step run stays interactive.
 */
export const CHUNK = 500;
const TABS = ["Timeline", "Workspace", "Run DAG", "Fleet", "Verify", "Attribution"];
function el(tag, text, cls) {
    const node = document.createElement(tag);
    if (text !== undefined)
        node.textContent = text;
    if (cls)
        node.className = cls;
    return node;
}
function pretty(value) {
    return typeof value === "string" ? value : JSON.stringify(value, null, 2);
}
async function get(path) {
    const res = await fetch(path, { credentials: "same-origin" });
    if (!res.ok)
        throw new Error(`${path}: ${res.status}`);
    return (await res.json());
}
function details(label, value) {
    if (value === null || value === undefined || value === "" || (typeof value === "object" && Object.keys(value).length === 0))
        return null;
    const d = el("details");
    d.append(el("summary", label), el("pre", pretty(value)));
    return d;
}
function stepRow(runId, step) {
    const li = el("li", undefined, `step kind-${step.kind}`);
    li.id = `step-${step.index}`;
    li.tabIndex = -1;
    const head = el("div", undefined, "meta");
    head.append(el("span", `#${step.index}`), el("b", ` ${step.kind}`));
    for (const part of [step.model, step.tool].filter(Boolean))
        head.append(el("span", ` · ${part}`));
    if (step.error)
        head.append(el("span", " error", "err"));
    const body = el("details");
    body.append(el("summary", "Details"));
    body.addEventListener("toggle", () => {
        if (!body.open || body.dataset.loaded)
            return;
        body.dataset.loaded = "1";
        void get(`/api/run/${encodeURIComponent(runId)}/step/${step.index}`).then((doc) => {
            body.append(el("p", `step ${doc.id}${doc.parent_ids.length > 1 ? ` · merges ${doc.parent_ids.length} parents` : ""}`, "meta"));
            for (const [label, value] of [["Input parts", doc.input_parts], ["Inputs / tool args", doc.inputs], ["Outputs / tool result", doc.outputs], ["Error", doc.error]]) {
                const block = details(label, value);
                if (block)
                    body.append(block);
            }
        });
    });
    li.append(head, body);
    return li;
}
export function renderTimeline(host, runId, steps) {
    const list = el("ol", undefined, "timeline");
    list.setAttribute("aria-label", "Run timeline");
    let shown = 0;
    const more = el("button", "", "more");
    const grow = () => {
        const frag = document.createDocumentFragment();
        for (const step of steps.slice(shown, shown + CHUNK))
            frag.append(stepRow(runId, step));
        list.append(frag);
        shown = Math.min(steps.length, shown + CHUNK);
        more.textContent = `Show more (${shown} of ${steps.length})`;
        more.hidden = shown >= steps.length;
    };
    more.addEventListener("click", grow);
    list.addEventListener("keydown", (ev) => {
        const at = document.activeElement?.closest("li.step");
        const next = ev.key === "j" || ev.key === "ArrowDown" ? at?.nextElementSibling : ev.key === "k" || ev.key === "ArrowUp" ? at?.previousElementSibling : null;
        if (next instanceof HTMLElement) {
            ev.preventDefault();
            next.focus();
        }
    });
    grow();
    host.replaceChildren(list, more);
    list.firstElementChild?.setAttribute("tabindex", "0");
}
async function renderWorkspace(host, run) {
    const last = Math.max(0, run.timeline.length - 1);
    const form = el("div", undefined, "controls");
    const step = el("input");
    step.type = "number";
    step.min = "0";
    step.max = String(last);
    step.value = String(last);
    step.setAttribute("aria-label", "Workspace at step");
    const base = el("input");
    base.type = "number";
    base.min = "0";
    base.max = String(last);
    base.value = "0";
    base.setAttribute("aria-label", "Diff from step");
    const go = el("button", "Show");
    const out = el("div");
    form.append(el("label", "Tree at step "), step, el("label", " diff from step "), base, go);
    const show = async () => {
        const id = encodeURIComponent(run.id);
        const tree = await get(`/api/run/${id}/tree?step=${step.value}`);
        const diff = await get(`/api/run/${id}/diff?a=${base.value}&b=${step.value}`);
        const files = el("ul", undefined, "tree");
        for (const [path, body] of Object.entries(tree))
            files.append(el("li", body === null ? `${path} (content not recorded)` : path));
        out.replaceChildren(el("h3", "Files"), Object.keys(tree).length ? files : el("p", "No recorded file writes."), el("h3", "Diff"));
        for (const [path, text] of Object.entries(diff)) {
            const d = details(path, text);
            if (d)
                out.append(d);
        }
    };
    go.addEventListener("click", () => void show());
    host.replaceChildren(form, out);
    await show();
}
function renderDag(host, run, runs) {
    const ul = el("ul", undefined, "dag");
    const parents = [...run.parents, ...(run.forked_from ? [run.forked_from] : [])];
    for (const p of parents)
        ul.append(el("li", `parent ${p}`));
    ul.append(el("li", `this run ${run.id}`, "self"));
    for (const r of runs)
        if (r.parents.includes(run.id) || r.forked_from === run.id)
            ul.append(el("li", `child ${r.id}`));
    const steps = el("p", `${run.timeline.filter((s) => s.parents > 1).length} merge steps; ${run.timeline.length} steps in all.`);
    host.replaceChildren(ul, steps);
}
function renderFleet(host, runs) {
    const groups = new Map();
    for (const r of runs) {
        const key = r.fleet && typeof r.fleet.id === "string" ? r.fleet.id : "";
        if (key)
            groups.set(key, [...(groups.get(key) || []), r]);
    }
    if (!groups.size) {
        host.replaceChildren(el("p", "No fleet records among these runs."));
        return;
    }
    const ul = el("ul", undefined, "fleet");
    for (const [id, members] of groups)
        ul.append(el("li", `fleet ${id}: ${members.map((m) => m.id.slice(0, 12)).join(", ")}`));
    host.replaceChildren(ul);
}
async function renderVerify(host, runId) {
    const box = el("div", "Checking…");
    box.setAttribute("aria-live", "polite");
    host.replaceChildren(box);
    const v = await get(`/api/run/${encodeURIComponent(runId)}/verify`);
    const worker = new Worker("verify-browser.js", { type: "module" });
    worker.onmessage = (ev) => {
        const b = ev.data;
        const table = el("table");
        for (const [what, state, by] of b.rows) {
            const tr = el("tr");
            tr.append(el("td", what), el("td", state, `state ${state}`), el("td", by));
            table.append(tr);
        }
        box.replaceChildren(el("p", b.label, `state ${b.state}`), table);
        for (const r of v.reasons || [])
            box.append(el("p", r, "meta"));
        box.append(el("p", `this browser: ${b.detail}`, "meta"));
        worker.terminate();
    };
    worker.postMessage({ verification: v, artifact: `/api/run/${encodeURIComponent(runId)}/artifact` });
}
async function renderAttribution(host, runId) {
    const rows = await get(`/api/run/${encodeURIComponent(runId)}/attribution`);
    if (!rows.length) {
        host.replaceChildren(el("p", "No recorded file writes."));
        return;
    }
    const table = el("table");
    for (const row of rows) {
        const tr = el("tr");
        tr.append(el("td", row.path), el("td", `step ${row.step}`), el("td", row.model || "-"));
        table.append(tr);
    }
    host.replaceChildren(table);
}
async function openRun(main, id, runs) {
    const run = await get(`/api/run/${encodeURIComponent(id)}`);
    const header = el("header");
    header.append(el("h2", `Run ${run.id}`), el("p", `${run.status} · ${run.model || "-"} · ${run.timeline.length} steps`, "meta"));
    if (run.user_prompt)
        header.append(details("Prompt", run.user_prompt));
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
            if (d) {
                const n = (i + d + TABS.length) % TABS.length;
                buttons[n].focus();
                void select(n);
            }
        });
        return b;
    });
    tabs.append(...buttons);
    const select = async (i) => {
        buttons.forEach((b, j) => { b.setAttribute("aria-selected", String(i === j)); b.tabIndex = i === j ? 0 : -1; });
        if (i === 0)
            renderTimeline(panel, run.id, run.timeline);
        else if (i === 1)
            await renderWorkspace(panel, run);
        else if (i === 2)
            renderDag(panel, run, runs);
        else if (i === 3)
            renderFleet(panel, runs);
        else if (i === 4)
            await renderVerify(panel, run.id);
        else
            await renderAttribution(panel, run.id);
    };
    main.replaceChildren(header, tabs, panel);
    await select(0);
}
export async function start() {
    const nav = document.getElementById("runs");
    const main = document.getElementById("main");
    const runs = await get("/api/runs");
    const ul = el("ul");
    for (const r of runs) {
        const b = el("button", `${r.id.slice(0, 12)} · ${r.status} · ${r.steps} steps`);
        b.addEventListener("click", () => void openRun(main, r.id, runs));
        const li = el("li");
        li.append(b);
        ul.append(li);
    }
    nav.replaceChildren(runs.length ? ul : el("p", "No runs found."));
    if (runs.length === 1)
        await openRun(main, runs[0].id, runs);
}
if (typeof document !== "undefined")
    void start();
