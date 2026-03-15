# Linear DoS

## Overview

The challenge gives us a regex pattern and an input string, then runs:

- `new RegExp(pattern, 'l')`
- `regex.test(input)`

inside a child process with a `2000 ms` timeout.

If the child times out three times in a row, we get the flag.

At first glance this looks impossible because the `l` flag is the experimental "linear" regexp engine. The trick is that "linear" here means linear in the input size for a fixed regex. The regex length is also attacker-controlled, so the real cost can still be roughly `O(N * M)` where:

- `N` = input length
- `M` = regex size

That is exactly what the challenge title hints at, and it matches the flag.

## Source Analysis

`runner.js` is the important part:

```js
for (let i = 0; i < 3; i++) {
  const result = spawnSync(
    NODE_PATH,
    [
      "--enable-experimental-regexp-engine",
      CHALLENGE_PATH,
      pattern,
      inputStr,
    ],
    {
      timeout: 2000,
      stdio: "inherit",
    }
  );

  if (result.error && result.error.code === "ETIMEDOUT") {
    continue;
  }

  process.exit(0);
}

console.log("Here is your flag:", FLAG);
```

So we need one `(pattern, input)` pair that individually exceeds `2 seconds` per run.

`challenge.js` adds the main constraints:

- `pattern.length + input.length <= 1800`
- ASCII printable characters only
- the regex must be accepted by `new RegExp(pattern, 'l')`

Many obviously bad regexes are rejected with:

```text
Cannot be executed in linear time
```

So the problem is not "find catastrophic backtracking". It is "find a regex that the linear engine accepts, but that is still expensive enough when both the regex and the text are large."

## Key Insight

The engine is still vulnerable to a regex-size DoS.

If the automaton has a lot of active states for each consumed character, then matching work scales with both:

- the number of characters in the input
- the number of states induced by the pattern

That gives an `O(NM)` style slowdown. With a total budget of `1800` bytes, that is enough to cross the remote `2000 ms` timeout.

In practice, the best family I found used repeated wildcard-heavy subexpressions built from `.*` under nested quantifiers. Many candidates were rejected by the engine, so I searched empirically against the exact challenge runtime (`node:25.8.1`, from the Dockerfile) and then verified the top candidates remotely.

## Winning Payload

The payload that worked remotely was:

```js
const unit = "(((.*)+){8}((.*)+){8})";
const repeat = 56;
const pattern = unit.repeat(repeat) + "X";
const input = "a".repeat(1800 - pattern.length);
```

This gives:

- `pattern.length = 1233`
- `input.length = 567`

So the total length is exactly `1800`.

The final regex does a lot of work on an all-`a` string before failing on the trailing `X`, and the remote service is slow enough that each run exceeds the `2000 ms` timeout.

## Why This Specific Pattern Works

The exact internal behavior of the experimental engine is not documented in enough detail to derive this payload analytically from first principles, so this was solved empirically.

What matters is:

- `.*` creates a very permissive sub-automaton
- wrapping it in `+`, then repeating those groups many times, keeps a large amount of pattern state alive
- concatenating many such blocks increases the regex-size factor `M`
- using a long all-`a` input makes the engine pay that cost for many positions before the final `X` mismatch

So while the engine avoids classic exponential backtracking, this pattern still behaves like a practical `O(NM)` denial of service.

## Reproduction

I added a solver script:

- [tools/solve.js](https://github.com/prathamgupta36/CTF-Writeups/blob/main/2026/tkbctf5_2026/misc/linear-dos/tools/solve.js)

Run:

```bash
node tools/solve.js
```

That script reuses `tools/remote_try.js`, which already handles the proof-of-work and sends the payload to the remote service.

The remote result was:

```text
round 0:
round 1:
round 2:
Here is your flag: tkbctf{O(NM)dosu~}
```

## Flag

`tkbctf{O(NM)dosu~}`
