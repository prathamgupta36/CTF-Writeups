const MAX_UNIT_LEN = Number(process.argv[2] || 14);
const KEEP_PER_LEN = Number(process.argv[3] || 12);

function benchUnit(unit) {
  let best = null;
  for (let n = 1; ; n++) {
    const pattern = unit.repeat(n) + "b";
    if (pattern.length > 1790) break;

    const input = "a".repeat(1800 - pattern.length);
    const started = Date.now();

    try {
      const re = new RegExp(pattern, "l");
      const compiled = Date.now();
      re.test(input);
      const ended = Date.now();
      const rec = {
        n,
        len: pattern.length,
        input: input.length,
        compile: compiled - started,
        test: ended - compiled,
        total: ended - started,
      };
      if (!best || rec.total > best.total) best = rec;
    } catch {
      return null;
    }
  }
  return best;
}

function add(set, value) {
  if (value.length <= MAX_UNIT_LEN) set.add(value);
}

let frontier = new Set(["a", "()"]);
const seen = new Set(frontier);
const scored = [];

for (let depth = 0; depth < 4; depth++) {
  const next = new Set();

  for (const x of frontier) {
    add(next, `(${x})`);
    add(next, `${x}?`);
    add(next, `(${x})?`);
    add(next, `(?:${x})?`);
    add(next, `(${x}|a)`);
    add(next, `(${x}|())`);
    add(next, `(${x}|a?)`);
    add(next, `(${x}${x})`);
    add(next, `(${x})(${x})`);
    add(next, `(?<=a)${x}`);
    add(next, `(?<!b)${x}`);
  }

  for (const x of frontier) {
    for (const y of frontier) {
      add(next, `(${x}|${y})`);
      add(next, `(?:${x}|${y})`);
      add(next, `(${x}${y})`);
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
    const best = benchUnit(unit);
    if (best) batch.push({ unit, best });
  }

  batch.sort((a, b) => b.best.total - a.best.total);
  const kept = batch.slice(0, KEEP_PER_LEN);
  frontier = new Set(kept.map((x) => x.unit));
  scored.push(...kept);
  console.log(JSON.stringify({ depth, kept }));
}

scored.sort((a, b) => b.best.total - a.best.total);
console.log(JSON.stringify({ top: scored.slice(0, 20) }, null, 2));
