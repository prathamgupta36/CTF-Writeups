# Jail Break

## Summary

The sandbox bans suspicious substrings in the raw input, but it still exposes the hidden `_secret` function through the globals dictionary.

## Solution

`jail.py` puts `_secret` inside `GLOBALS`:

```python
GLOBALS = {"__builtins__": SAFE_BUILTINS, "_secret": _secret}
```

The filter only blocks literal substrings such as `secret`, `_key`, and `_enc` if they appear directly in the submitted source. That means the name can be reconstructed at runtime.

This payload bypasses the filter and calls the hidden function:

```python
print(vars()['_'+'se'+'cret']())
```

- `vars()` returns the active global namespace inside the jailed `exec`.
- `'_ '+'se'+'cret'` avoids the literal banned substring `secret` in the source.
- The resulting function call prints the flag.

## Flag

`utflag{py_ja1l_3sc4p3_m4st3r}`
