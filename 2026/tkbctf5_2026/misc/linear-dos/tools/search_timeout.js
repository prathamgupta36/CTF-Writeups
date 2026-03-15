const path = require("path");
const { spawnSync } = require("child_process");

const MAX_UNIT_LEN = Number(process.argv[2] || 14);
const KEEP_PER_DEPTH = Number(process.argv[3] || 16);
const MAX_DEPTH = Number(process.argv[4] || 4);
const TIMEOUT_MS = Number(process.argv[5] || 2200);

const challengePath = path.join(__dirname, "..", "_src", "linear-dos", "challenge.js");

function runCandidate(pattern, input) {
  const started = Date.now();
  const result = spawnSync(
    process.execPath,
    ["--enable-experimental-regexp-engine", challengePath, pattern, input],
    {
      encoding: "utf8",
      timeout: TIMEOUT_MS,
    }
  );
  const elapsed = Date.now() - started;

  if (result.error && result.error.code === "ETIMEDOUT") {
    return { timeout: true, elapsed };
  }

  return {
    timeout: false,
    elapsed,
    status: result.status,
    stdout: (result.stdout || "").trim(),
    stderr: (result.stderr || "").trim(),
  };
}

function sampleNs(unit) {
  const maxN = Math.floor((1790 - 1) / unit.length);
  const seen = new Set();
  const picked = [];
  const fractions = [1, 0.97, 0.94, 0.9, 0.85, 0.8, 0.75, 0.7, 0.65, 0.6, 0.55, 0.5, 0.45, 0.4, 0.35, 0.3];

  for (const fraction of fractions) {
    const n = Math.max(1, Math.floor(maxN * fraction));
    if (seen.has(n)) continue;
    seen.add(n);
    picked.push(n);
  }

  return picked;
}

function benchUnit(unit) {
  let best = null;

  for (const n of sampleNs(unit)) {
    const pattern = unit.repeat(n) + "b";
    const input = "a".repeat(1800 - pattern.length);
    const result = runCandidate(pattern, input);
    const rec = { unit, n, len: pattern.length, input: input.length, ...result };

    if (!best || rec.elapsed > best.elapsed || rec.timeout) {
      best = rec;
    }

    if (rec.timeout) {
      return rec;
    }
  }

  return best;
}

function add(out, value) {
  if (0 < value.length && value.length <= MAX_UNIT_LEN) {
    out.add(value);
  }
}

let frontier = new Set(["a", "()", "a?", "(a)?", "(a|())"]);
const seen = new Set(frontier);
const scored = [];

for (let depth = 0; depth < MAX_DEPTH; depth++) {
  const next = new Set();

  for (const x of frontier) {
    add(next, `(${x})`);
    add(next, `(?:${x})`);
    add(next, `${x}?`);
    add(next, `(${x})?`);
    add(next, `(?:${x})?`);
    add(next, `${x}*`);
    add(next, `(${x})*`);
    add(next, `(?:${x})*`);
    add(next, `${x}+`);
    add(next, `(${x})+`);
    add(next, `(?:${x})+`);
    add(next, `(${x}|a)`);
    add(next, `(${x}|())`);
    add(next, `(${x}|a?)`);
    add(next, `(${x}|${x}?)`);
    add(next, `(${x}${x})`);
    add(next, `(${x})(${x})`);
    add(next, `(?<=a)${x}`);
    add(next, `(?<!b)${x}`);
    add(next, `(?=a)${x}`);
    add(next, `(?!b)${x}`);
  }

  for (const x of frontier) {
    for (const y of frontier) {
      add(next, `(${x}|${y})`);
      add(next, `(?:${x}|${y})`);
      add(next, `(${x}${y})`);
      add(next, `(?:${x}${y})`);
    }
  }

  const fresh = [];
  for (const candidate of next) {
    if (seen.has(candidate)) continue;
    seen.add(candidate);
    fresh.push(candidate);
  }

  const batch = [];
  for (const unit of fresh) {
    const rec = benchUnit(unit);
    if (!rec) continue;
    batch.push(rec);

    if (rec.timeout) {
      console.log(JSON.stringify({ depth, hit: rec }, null, 2));
      process.exit(0);
    }
  }

  batch.sort((a, b) => b.elapsed - a.elapsed);
  const kept = batch.slice(0, KEEP_PER_DEPTH);
  frontier = new Set(kept.map((x) => x.unit));
  scored.push(...kept);
  console.log(JSON.stringify({ depth, kept }, null, 2));
}

scored.sort((a, b) => b.elapsed - a.elapsed);
console.log(JSON.stringify({ top: scored.slice(0, 30) }, null, 2));
