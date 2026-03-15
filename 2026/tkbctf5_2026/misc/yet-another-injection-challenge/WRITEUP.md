# yet-another-injection-challenge

Flag: `tkbctf{s0_wh4t'5_th3_n3x7_1nj3c710n_ch4ll3ng3?}`

## Challenge

The service is a tiny Python wrapper around `yq`:

```python
while expr := input("expr: ").strip():
    if any(bloked in expr for bloked in ["\"", ".", "env", "load", "file"]):
        print("blocked")
        continue
    try:
        subprocess.run(["yq", "-n", expr], capture_output=True, timeout=2, check=True)
        print("ok")
    except:
        print("error")
```

Important details:

- our input is passed directly as the `yq` expression
- only five substrings are blocked: `"`, `.`, `env`, `load`, `file`
- stdout/stderr from `yq` are discarded
- the only observable result is `ok` or `error`

The intended target is `/flag.txt`, but the obvious payload `load("/flag.txt")` is filtered.

## Idea

The blacklist is far too small for a language as large as `yq`.

Even with those substrings blocked, many useful features still remain available:

- `eval(...)`
- `@base64` and `@base64d`
- `split(style)`, `join(style)`
- `kind`, `tag`, `match`, `keys`, `upcase`
- indexing like `(expr)[i]`

So the problem becomes:

1. build forbidden strings such as `load("/flag.txt")` without ever typing them literally
2. execute that string with `eval(...)`
3. turn the result into a boolean oracle, because command output is hidden

## Bypassing the blacklist

The key trick is to synthesize characters from harmless built-ins.

For example:

- `kind` evaluates to `scalar`
- `tag` evaluates to `!!null`
- `kind|@json` evaluates to `"scalar"`
- `({(kind):1}|@xml)` evaluates to `<scalar>1</scalar>`
- `({(kind):{(kind):1}}|@props)` evaluates to `scalar.scalar = 1`

Those outputs contain lots of useful characters. Since `yq` supports:

- splitting strings: `split(style)`
- indexing arrays: `(...)[i]`
- joining strings: `join(style)`

we can extract single characters and assemble arbitrary strings.

For characters we still cannot obtain directly, we can recurse through base64:

```yq
(([expr_for_Y, expr_for_Q, expr_for_equals, expr_for_equals]|join(style))|@base64d)
```

That gives one decoded byte without ever writing the byte literally.

Once we can build strings, we can construct this hidden payload:

```yq
(load("/flag.txt")|test("^tkbctf\\{...")) or error(1)
```

Then wrap it in:

```yq
eval(...)
```

If the regex matches, the expression returns true and the service prints `ok`.
If it does not match, `error(1)` is executed and the service prints `error`.

That turns the challenge into a blind regex oracle on `/flag.txt`.

## Extracting the flag

Because the service timeout is only 2 seconds, very large regex character classes are unreliable.
The stable approach is to recover the flag one character at a time with small buckets:

- `[ -/]`
- `[0-9]`
- `[:-@]`
- `[A-Z]`
- `[\[\]\\^_`]`
- `[a-z]`
- `[{|~]`

For each position:

1. test whether the flag already ends with `}`
2. find which bucket contains the next character
3. binary-search inside that bucket

This keeps every probe short enough for the remote service.

## Solver

[solve.py](https://github.com/prathamgupta36/CTF-Writeups/blob/main/2026/tkbctf5_2026/misc/yet-another-injection-challenge/solve.py) automates the full exploit:

1. downloads the exact `yq` version used by the challenge
2. builds a character-expression map from safe `yq` primitives
3. synthesizes forbidden payloads through base64 decoding
4. queries the remote service as a boolean oracle
5. reconstructs the flag incrementally

Example run:

```bash
python3 solve.py
```

It can also resume from a known prefix:

```bash
python3 solve.py --prefix "tkbctf{s0_wh4t'5_th3_n3x7_1nj3c710n_ch4ll3ng3?"
```

## Why it works

The challenge assumes that blocking a few dangerous substrings is enough to secure a general-purpose expression language. It is not.

The real bugs are:

- raw user input is evaluated as `yq` code
- the defense is substring filtering instead of capability restriction
- dangerous operators such as `eval`, `@base64d`, and regex testing remain available
- the service leaks one bit of information per query through `ok` vs `error`

That is enough to recover the entire flag without ever printing file contents directly.
