# SDK Examples

This folder contains runnable examples that exercise the current SDK surfaces:

- JavaScript: `examples/sdk/javascript/surface-demo.cjs`
- Julia: `examples/sdk/julia/surface_demo.jl`
- JVM: `examples/sdk/jvm/src/main/java/io/rulia/examples/SdkSurfaceDemo.java`

From `examples/`, run:

```bash
make sdk-js-example
make sdk-julia-example
make sdk-jvm-example
```

Or run all three:

```bash
make sdk-examples
```

If `RULIA_LIB_PATH` and `RULIA_MANIFEST_URL` are both unset, Julia/JVM SDK examples are skipped and the JS SDK example still runs.

## Native Runtime Setup (Julia + JVM)

Julia and JVM examples need access to `librulia` and support two loading modes:

- `RULIA_MANIFEST_URL` (+ optional `RULIA_VERSION`, default `0.1.0`) to install/load via SDK installer
- `RULIA_LIB_PATH` to load an already-installed native library directly

Example:

```bash
RULIA_LIB_PATH=/absolute/path/to/librulia.dylib make sdk-julia-example
RULIA_LIB_PATH=/absolute/path/to/librulia.dylib make sdk-jvm-example
```
