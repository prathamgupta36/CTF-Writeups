const [unit, maxMillisArg] = process.argv.slice(2);

if (!unit) {
  console.error("usage: node bench_unit.js <unit> [maxMillis]");
  process.exit(1);
}

const maxMillis = maxMillisArg ? Number(maxMillisArg) : 5000;
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
    if (rec.total >= maxMillis) {
      console.log(JSON.stringify({ unit, hit: rec, best }));
      process.exit(0);
    }
  } catch (error) {
    break;
  }
}

if (best) {
  console.log(JSON.stringify({ unit, best }));
} else {
  console.log(JSON.stringify({ unit, error: "unsupported" }));
}
