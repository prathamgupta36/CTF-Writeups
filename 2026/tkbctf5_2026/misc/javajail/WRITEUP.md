# javajail

Flag: `tkbctf{my_fr13nd_c0ndy_br34k5_y0u_ou7_0f_j4il!}`

## Challenge

The server accepts a base64-encoded Java class and rejects it if any of these checks fail:

- class size must be at most 650 bytes
- the raw class bytes must not contain the string `Runtime`
- ASM scans the methods and rejects any `invoke*` instruction

Then it loads the class and calls `run()`.

## Idea

The filter only looks at bytecode instructions inside methods. It does not reject:

- `ConstantDynamic`
- bootstrap method handles
- field handles such as `H_GETSTATIC`
- method handles embedded in the constant pool

That means the method body can stay tiny and invoke no methods directly, while the real work happens during dynamic-constant resolution.

## Exploit

`misc/javajail/GenerateExploit.java` builds a 642-byte class with one `run()` method:

1. `stream` is a `ConstantDynamic` that constructs `new FileInputStream("/flag.txt")`
2. `out` is a `ConstantDynamic` that resolves `System.out` through an `H_GETSTATIC` handle
3. `done` is a `ConstantDynamic` that calls `InputStream.transferTo(OutputStream)` on those two objects
4. `run()` only does `ldc done; pop; return`

Because the server's scan only flags `visitMethodInsn` and `visitInvokeDynamicInsn`, this payload passes the jail while still making the bootstrap machinery execute the file read and write.

## Reproduction

Generate the payload:

```bash
javac --add-exports java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED GenerateExploit.java
java --add-exports java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED GenerateExploit
```

Send the emitted base64 to the service:

```bash
B64=$(java --add-exports java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED -cp . GenerateExploit | tail -n 1)
printf '%s\n' "$B64" | nc 35.194.108.145 41992
```

The service prints the flag.
