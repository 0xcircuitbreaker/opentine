// Recompute an opentine.trends/1 export in a browser or Node (opentine 0.72).
//
// The same arithmetic as opentine/_trends.py and opentine/_trend_math.py:
// integers (BigInt) for scores, rates, costs and the 0.57 bootstrap, and only
// IEEE-754 double + - * / and comparisons for the time-horizon fit, so the
// result is the same bytes the CLI reported. See docs/TRENDS.md.
//
//   import { compute, canonical, check } from "./recompute.mjs";
//   check(exportObject)  // {ok, recomputed, reported}
//
//   node recompute.mjs EXPORT.json   // prints canonical JSON of compute(export)

const MASK = (1n << 64n) - 1n;
const LN2_HI = 6.9314718036912381649e-1;
const LN2_LO = 1.90821492927058770002e-10;
const INV_LN2 = 1.442695040888963387;
const SQRT2 = 1.41421356237309514547;
const STEPS = 60, SQRT_STEPS = 8, EXP_TERMS = 18, LOG_TERMS = 30;
const MICRO = 1000000n;
const CONVENTION = "opentine.trends/1";
const METRICS = ["score", "pass_rate"];

function fnv1a64(text) {
  let value = 0xcbf29ce484222325n;
  for (const byte of new TextEncoder().encode(text)) {
    value = ((value ^ BigInt(byte)) * 0x100000001b3n) & MASK;
  }
  return value;
}

class SplitMix {
  constructor(stream) { this.state = fnv1a64(stream); }
  next64() {
    this.state = (this.state + 0x9e3779b97f4a7c15n) & MASK;
    let z = this.state;
    z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & MASK;
    z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & MASK;
    return z ^ (z >> 31n);
  }
  randrange(n) {
    const big = BigInt(n);
    const limit = (1n << 64n) - ((1n << 64n) % big);
    for (;;) {
      const draw = this.next64();
      if (draw < limit) return Number(draw % big);
    }
  }
}

function pow2(value, k) {
  while (k > 0) { value = value * 2.0; k -= 1; }
  while (k < 0) { value = value * 0.5; k += 1; }
  return value;
}

function exp(x) {
  if (x !== x) return x;
  if (x > 709.0) return Infinity;
  if (x < -745.0) return 0.0;
  const k = Math.floor(x * INV_LN2 + 0.5);
  const r = (x - k * LN2_HI) - k * LN2_LO;
  let term = 1.0, total = 1.0;
  for (let i = 1; i < EXP_TERMS; i++) { term = term * r / i; total = total + term; }
  return pow2(total, k);
}

function log(x) {
  if (!(x > 0.0) || x === Infinity) throw new Error("log needs a positive finite number");
  let e = 0, m = x;
  while (m >= 2.0) { m = m * 0.5; e += 1; }
  while (m < 1.0) { m = m * 2.0; e -= 1; }
  if (m > SQRT2) { m = m * 0.5; e += 1; }
  const f = (m - 1.0) / (m + 1.0);
  const f2 = f * f;
  let term = f, total = 0.0;
  for (let i = 0; i < LOG_TERMS; i++) { total = total + term / (2 * i + 1); term = term * f2; }
  return e * LN2_HI + (2.0 * total + e * LN2_LO);
}

function sigmoid(z) { return 1.0 / (1.0 + exp(-z)); }

function fit(bins) {
  let a = 0.0, b = 0.0;
  for (let s = 0; s < STEPS; s++) {
    let ga = 0.0, gb = 0.0, haa = 0.0, hab = 0.0, hbb = 0.0;
    for (const [x, tries, wins] of bins) {
      const p = sigmoid(a + b * x);
      const w = tries * p * (1.0 - p);
      const resid = wins - tries * p;
      ga = ga + resid; gb = gb + x * resid;
      haa = haa + w; hab = hab + w * x; hbb = hbb + w * x * x;
    }
    const det = haa * hbb - hab * hab;
    if (!(det > 1e-12)) return null;
    const da = (hbb * ga - hab * gb) / det;
    const db = (haa * gb - hab * ga) / det;
    a = a + da; b = b + db;
    if (!(Math.abs(a) < 1e6 && Math.abs(b) < 1e6)) return null;
    if (Math.abs(da) + Math.abs(db) < 1e-10) return [a, b, haa, hab, hbb];
  }
  return null;
}

function sqrt(value) {
  if (!(value > 0.0)) return 0.0;
  let guess = 1.0;
  while (guess * guess < value) guess = guess * 2.0;
  while (guess * guess > value * 4.0) guess = guess * 0.5;
  for (let i = 0; i < SQRT_STEPS; i++) guess = 0.5 * (guess + value / guess);
  return guess;
}

function x50(params) {
  if (params === null || !(params[1] < 0.0)) return null;
  const [a, b, haa, hab, hbb] = params;
  const det = haa * hbb - hab * hab;
  const point = -a / b;
  const variance = (hbb - 2.0 * point * hab + point * point * haa) / det / (b * b);
  return [point, sqrt(variance)];
}

function microText(value) {
  let units = BigInt(Math.floor(value * 1e6 + 0.5));
  let sign = "";
  if (units < 0n) { sign = "-"; units = -units; }
  return `${sign}${units / MICRO}.${String(units % MICRO).padStart(6, "0")}`;
}

// alpha as an exact fraction [num, den] from its decimal string
function fraction(text) {
  const [whole, part = ""] = text.split(".");
  const den = 10n ** BigInt(part.length);
  return [BigInt(whole) * den + BigInt(part || "0"), den];
}

function quantileIndex([num, den], resamples) {
  const r = BigInt(resamples);
  const twice = 2n * den;
  const low = (num * r) / twice; // floor(alpha/2 * R)
  const high = ((twice - num) * r + twice - 1n) / twice - 1n; // ceil((1 - alpha/2) * R) - 1
  return [Number(low), Number(high)];
}

// p / q as a six-place decimal, rounded half-even (opentine._eval_stats.text)
function text(p, q) {
  let num = BigInt(p) * MICRO, den = BigInt(q);
  if (den < 0n) { num = -num; den = -den; }
  const negative = num < 0n;
  if (negative) num = -num;
  let units = num / den;
  const twice = 2n * (num % den);
  if (twice > den || (twice === den && units % 2n === 1n)) units += 1n;
  if (units === 0n) return "0.000000";
  return `${negative ? "-" : ""}${units / MICRO}.${String(units % MICRO).padStart(6, "0")}`;
}

function micro(score) {
  const [whole, part = ""] = score.split(".");
  return Number(BigInt(whole) * MICRO + BigInt((part + "000000").slice(0, 6)));
}

function bootstrap(diffs, rng, resamples, alpha) {
  const n = diffs.length;
  const sums = [];
  for (let r = 0; r < resamples; r++) {
    let total = 0;
    for (let i = 0; i < n; i++) total += diffs[rng.randrange(n)];
    sums.push(total);
  }
  sums.sort((x, y) => x - y);
  const [lo, hi] = quantileIndex(alpha, resamples);
  const low = sums[lo], high = sums[hi];
  const scale = BigInt(n) * MICRO;
  return { ci: [text(low, scale), text(high, scale)], significant: low > 0 || high < 0 };
}

function rng(data, variant, metric) {
  return new SplitMix(`${CONVENTION}:${data.seed}:${variant}:${metric}`);
}

function columns(items) {
  return {
    score: items.map((i) => micro(i.score)),
    pass_rate: items.map((i) => (i.passed ? 1000000 : 0)),
  };
}

function sum(values) { return values.reduce((x, y) => x + y, 0); }

function level(data, variant, metric, values, alpha) {
  const n = values.length;
  if (!n) return { mean: null, ci: null };
  const ci = bootstrap(values, rng(data, variant, metric), data.resamples, alpha).ci;
  return { mean: text(sum(values), BigInt(n) * MICRO), ci };
}

function bound(x) {
  if (x === Infinity || x === -Infinity) return null;
  return microText(exp(x * LN2_HI + x * LN2_LO));
}

function horizon(items, alpha, resamples, stream) {
  const timed = items.filter((i) => i.minutes !== null && i.minutes !== undefined);
  const lengths = [...new Set(timed.map((i) => i.minutes))].sort((x, y) => Number(x) - Number(y));
  const grid = lengths.map((m) => [m, log(Number(m)) * INV_LN2]);
  const where = new Map(lengths.map((m, k) => [m, k]));
  const rows = timed.map((i) => [where.get(i.minutes), Boolean(i.passed)]);
  const out = { n: rows.length, lengths: grid.length, minutes: null, ci: null, reason: null,
    failed_resamples: 0 };
  if (grid.length < 2) { out.reason = "fewer-than-two-lengths"; return out; }
  const solve = (sample) => {
    const tries = grid.map(() => 0), wins = grid.map(() => 0);
    for (const [k, ok] of sample) { tries[k] += 1; wins[k] += ok ? 1 : 0; }
    const cells = [];
    for (let k = 0; k < grid.length; k++) if (tries[k]) cells.push([grid[k][1], tries[k], wins[k]]);
    return x50(fit(cells));
  };
  const point = solve(rows);
  if (point === null || !(point[1] > 0.0)) { out.reason = "no-fit"; return out; }
  const [x, se] = point;
  out.minutes = bound(x);
  const passes = rows.filter(([, ok]) => ok).length;
  const edge = passes * 2 >= rows.length ? Infinity : -Infinity;
  const draws = [];
  for (let r = 0; r < resamples; r++) {
    const sample = rows.map(() => rows[stream.randrange(rows.length)]);
    const got = solve(sample);
    draws.push(got === null || !(got[1] > 0.0) ? edge : (got[0] - x) / got[1]);
  }
  draws.sort((p, q) => (p < q ? -1 : p > q ? 1 : 0));
  const [lo, hi] = quantileIndex(alpha, resamples);
  out.ci = [bound(x - draws[hi] * se), bound(x - draws[lo] * se)];
  out.failed_resamples = draws.filter((d) => d === Infinity || d === -Infinity).length;
  return out;
}

function versus(data, row, parent, alpha) {
  const mine = new Map(row.items.map((i) => [i.item, i]));
  const theirs = new Map(parent.items.map((i) => [i.item, i]));
  const shared = [...mine.keys()].filter((k) => theirs.has(k)).sort(byCodeUnits);
  const out = { parent: parent.variant, n: shared.length, regressions: [] };
  for (const metric of METRICS) {
    const a = columns(shared.map((k) => theirs.get(k)))[metric];
    const b = columns(shared.map((k) => mine.get(k)))[metric];
    const diffs = a.map((x, i) => b[i] - x);
    if (!diffs.length) { out[metric] = { delta: null, ci: null, significant: false }; continue; }
    const stream = rng(data, row.variant, `${metric}-vs:${parent.variant}`);
    const test = bootstrap(diffs, stream, data.resamples, alpha);
    const total = sum(diffs);
    out[metric] = { delta: text(total, BigInt(diffs.length) * MICRO), ci: test.ci,
      significant: test.significant };
    if (test.significant && total < 0) out.regressions.push(metric);
  }
  return out;
}

function byCodeUnits(x, y) { return x < y ? -1 : x > y ? 1 : 0; }

function variantRow(data, row, byId, alpha) {
  const out = { variant: row.variant, generation: row.generation, parents: row.parents,
    flags: row.flags, n: row.items.length };
  const cols = columns(row.items);
  for (const metric of METRICS) out[metric] = level(data, row.variant, metric, cols[metric], alpha);
  const passes = row.items.filter((i) => i.passed).length;
  const cost = row.cost_micro_usd;
  out.cost_per_success = cost === null || cost === undefined || !passes
    ? null : text(cost, BigInt(passes) * MICRO);
  out.horizon = horizon(row.items, alpha, data.resamples, rng(data, row.variant, "horizon"));
  out.vs_parents = row.parents.filter((p) => byId.has(p) && byId.get(p).items.length)
    .map((p) => versus(data, row, byId.get(p), alpha));
  return out;
}

function generations(rows) {
  const out = new Map();
  for (const row of rows) {
    if (!out.has(row.generation)) {
      out.set(row.generation, { generation: row.generation, variants: 0, flagged: 0,
        regressions: 0, best: null });
    }
    const gen = out.get(row.generation);
    gen.variants += 1;
    gen.flagged += row.flags.length ? 1 : 0;
    gen.regressions += row.vs_parents.filter((v) => v.regressions.length).length;
    const mean = row.score.mean;
    if (mean !== null && !row.flags.length
        && (gen.best === null || micro(mean) > micro(gen.best.score))) {
      gen.best = { variant: row.variant, score: mean, horizon_minutes: row.horizon.minutes };
    }
  }
  return [...out.keys()].sort((x, y) => x - y).map((g) => out.get(g));
}

export function compute(data) {
  if (data.convention !== CONVENTION) throw new Error(`not an ${CONVENTION} export`);
  const alpha = fraction(data.alpha);
  const byId = new Map(data.variants.map((row) => [row.variant, row]));
  const rows = data.variants.map((row) => variantRow(data, row, byId, alpha));
  const regressions = [];
  for (const r of rows) {
    for (const v of r.vs_parents) {
      if (v.regressions.length) {
        regressions.push({ variant: r.variant, parent: v.parent, metrics: v.regressions });
      }
    }
  }
  const flags = [...new Set(rows.flatMap((r) => r.flags))].sort(byCodeUnits);
  return { convention: CONVENTION, alpha: data.alpha, seed: data.seed,
    resamples: data.resamples, variants: rows, generations: generations(rows), regressions,
    flags };
}

// RFC 8785 for the values an export holds: strings, safe integers, booleans, null.
export function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const keys = Object.keys(value).sort(byCodeUnits);
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
}

export function check(exported) {
  const { reported, ...data } = exported;
  const recomputed = canonical(compute(data));
  return { ok: recomputed === canonical(reported), recomputed, reported: canonical(reported) };
}

const isMain = typeof process !== "undefined" && process.argv && process.argv[1]
  && import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/").split("/").pop());
if (isMain) {
  const { readFileSync } = await import("node:fs");
  const { reported: _ignored, ...data } = JSON.parse(readFileSync(process.argv[2], "utf8"));
  process.stdout.write(canonical(compute(data)) + "\n");
}
