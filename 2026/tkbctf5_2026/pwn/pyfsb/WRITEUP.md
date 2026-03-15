# PyFSB

Flag: `tkbctf{n3w_463_0f_f5b-805a5dd8f03016053bf77528ec56265b7c593e6612d54a458258e5e2eba51ab0}`

## Challenge

The service is a Python loop:

```python
print("welcome to fsb service")

import fsb
while True:
    print(fsb.pwn())
```

The native extension is the actual bug:

```c
static PyObject *pwn(PyObject *self, PyObject *args) {
  char request[0x100];
  if (fgets(request, 0x100, stdin) == NULL)
    return NULL;
  request[strcspn(request, "\n")] = 0;

  return Py_BuildValue(request);
}
```

`Py_BuildValue` expects a format string followed by matching variadic arguments. Here the user fully controls the format string, but the function passes no variadic arguments at all. That turns this into a varargs format-string bug.

## Exploit

On x86-64 SysV, `Py_BuildValue` reads the first variadic arguments from registers and then continues from the stack. At the call site, the local `request` buffer itself is sitting at `rsp`, so after consuming the register-backed arguments, later format units start treating bytes from our input buffer as 8-byte arguments.

Two-stage exploit:

1. Send `(` + `K` * 32 + `)` to dump 64-bit values with `K`.
2. One leaked stack pointer is at tuple index 17. Locally that pointer is `rsp + 0xc8`, so `rsp = leak[17] - 0xc8`.
3. Send a binary payload that uses `O&` after enough dummy `K` specifiers to reach fully controlled stack slots.
4. Put the fixed non-PIE address of `PyRun_SimpleString` (`0x4b5892` in the provided Ubuntu 24.04 `python3`) in the controlled slot.
5. Point its argument at a Python command stored later in the same input buffer:

```python
import glob;print(open(glob.glob('flag*')[0]).read())
```

`PyRun_SimpleString` executes the code and prints the flag before the process dies from the bogus return value being treated as a `PyObject *`.

## Solver

Exploit script: [solve.py](https://github.com/prathamgupta36/CTF-Writeups/blob/main/2026/tkbctf5_2026/pwn/pyfsb/solve.py)

Run:

```bash
python3 solve.py
```

It leaks the stack address, builds the second-stage payload, triggers `PyRun_SimpleString`, and extracts the flag from the server output.
