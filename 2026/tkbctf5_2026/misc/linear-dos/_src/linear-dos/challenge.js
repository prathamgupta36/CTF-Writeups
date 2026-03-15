try {
  new RegExp('(a*)*b', 'l').test('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
} catch {
  console.error('The "l" regex flag is not supported (try `node --enable-experimental-regexp-engine`)');
  process.exit(1);
}

const [pattern, inputString] = process.argv.slice(2);

if (typeof pattern != "string" || typeof inputString != "string") {
  console.error("Usage: node index.js <pattern> <input>");
  process.exit(1);
}

const totalLength = pattern.length + inputString.length;
if (1800 < totalLength) {
  console.error('Input lengths exceed the limit');
  process.exit(1);
}
if ([...pattern, ...inputString].some(x => x < " " || "\x80" <= x)) {
  console.error('Input contains invalid characters');
  process.exit(1);
}

try {
  const regex = new RegExp(pattern, 'l');

  const startTime = process.hrtime.bigint();
  regex.test(inputString);
  const endTime = process.hrtime.bigint();

  const tookMs = (endTime - startTime) / BigInt(1e6)
  console.log(`Done! Tooks ${tookMs} ms`);
} catch (error) {
  console.error('Invalid regex pattern or execution error');
  process.exit(1);
}
