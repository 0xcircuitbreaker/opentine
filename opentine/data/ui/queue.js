// tine ui oversight queue view (0.64). Renders /api/oversight/queue as text
// nodes only; the state shown is exactly the JSON `tine oversight queue --json`
// prints, including its digest.
const summary = document.getElementById("summary");
const body = document.querySelector("#queue tbody");

function cell(row, text) {
  const td = document.createElement("td");
  td.textContent = text;
  row.appendChild(td);
}

async function load() {
  const res = await fetch("api/oversight/queue");
  const data = await res.json();
  if (!res.ok) {
    summary.textContent = data.error || "queue unavailable";
    return;
  }
  const c = data.counts;
  summary.textContent = `${c.pending} pending, ${c.approved} approved, ${c.rejected} rejected, ` +
    `${c.unrouted} unrouted ` +
    `(policy ${data.policy.status}; digest ${data.digest})`;
  for (const item of data.items) {
    const row = document.createElement("tr");
    cell(row, item.state);
    cell(row, item.tiers.map((t) => `${t.tier} ${t.approvals}/${t.k}`).join(", "));
    cell(row, item.source);
    cell(row, item.opened_at || "");
    cell(row, item.item);
    body.appendChild(row);
  }
}

load().catch(() => {
  summary.textContent = "queue unavailable";
});
