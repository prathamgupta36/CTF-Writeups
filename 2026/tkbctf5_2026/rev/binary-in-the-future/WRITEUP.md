# BINARY IN THE FUTURE.

- Status: solved and submitted
- Flag: `tkbctf{AMX-AVX512_executes_only_on_cpus_made_of_diamond}`

## Challenge

The binary refuses to run on the local host and expects Intel SDE with `-future`. Static triage shows:

- it reads exactly 48 bytes of input,
- it transforms them into a 192-byte buffer,
- it compares that buffer against a fixed 192-byte blob with `memcmp`,
- on success it prints `tkbctf{%s}` using the original input.

So the task is to recover the 48-byte preimage of that final `memcmp`.

## Key observation

Using the supplied Dockerfile and an `LD_PRELOAD` shim on `memcmp`, the final transformed buffer can be dumped for any chosen 48-byte input. Probing the binary shows:

- the transform is linear over the input bytes modulo 256,
- the 48-byte input splits into 4 independent groups of 12 bytes,
- each 12-byte group affects exactly one 48-byte output block.

That reduces the problem to four separate linear systems over `Z/256Z`.

## Instrumentation

A preload shim was used to dump both `memcmp` arguments:

```c
int memcmp(const void *s1, const void *s2, size_t n) {
    dump_hex("memcmp-left", s1, n);
    dump_hex("memcmp-right", s2, n);
    return real_memcmp(s1, s2, n);
}
```

Built with:

```bash
gcc -shared -fPIC -O2 -o memcmp_dump.so memcmp_dump.c -ldl
```

Run under the challenge container:

```bash
docker build -t tkb-binary-future:latest rev/binary-in-the-future/binary-in-the-future
docker run --rm -i \
  -e LD_PRELOAD=/host/memcmp_dump.so \
  -v "$PWD/rev/binary-in-the-future/memcmp_dump.so:/host/memcmp_dump.so:ro" \
  tkb-binary-future:latest
```

## Solve strategy

1. Use the all-`0x01` input as a baseline.
2. For each position `i`, rerun with byte `i` changed from `0x01` to `0x02`.
3. The delta in the dumped `memcmp-left` buffer is the column vector for that input byte.
4. For each 12-byte block, solve:

```text
M * (x - 1) = target_block - baseline_block  (mod 256)
```

where `M` is the 48x12 matrix built from the per-byte deltas.

The four recovered 12-byte blocks are:

```text
AMX-AVX512_e
xecutes_only
_on_cpus_mad
e_of_diamond
```

Concatenating them gives the required input:

```text
AMX-AVX512_executes_only_on_cpus_made_of_diamond
```

## Result

The binary therefore prints:

```text
tkbctf{AMX-AVX512_executes_only_on_cpus_made_of_diamond}
```
