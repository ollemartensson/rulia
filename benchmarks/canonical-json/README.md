# Canonical JSON Optimization Competition

This benchmark suite tracks canonical JSON + SHA-256 throughput across language implementations and browser WASM.

## Lanes

- `rust` (native)
- `julia` (native)
- `java` (native)
- `wasm-browser` (Chromium via Playwright, optional)

## Profiles

- `base`: shared contract vectors from `examples/contracts/canon_vectors/*.json`
- `stress`: synthetic expansion of the same vectors (larger nested payload mix)

Each lane validates canonical bytes + SHA-256 against the contract vectors before timing.

## Run A Round

From repository root:

```bash
benchmarks/canonical-json/run.sh
```

Label a round (useful for optimization iterations):

```bash
ROUND=opt-rust-1 benchmarks/canonical-json/run.sh
```

## Key Environment Variables

- `RUNS` (default `7`): repeated runs per lane/profile
- `BASE_ITERATIONS` (default `50000`)
- `BASE_WARMUP` (default `5000`)
- `STRESS_ITERATIONS` (default `5000`)
- `STRESS_WARMUP` (default `500`)
- `ENABLE_JAVA_LANE` (default `auto`): `1` require Java lane, `0` skip, `auto` run only if `canonBench` task exists
- `ENABLE_WASM_BROWSER` (default `1`): `0` to skip browser WASM lane
- `ENSURE_PLAYWRIGHT_DEPS` (default `0`): set `1` to run `npm ci` in `examples/tests/playwright`
- `ENSURE_PLAYWRIGHT_BROWSER` (default `0`): set `1` to run `npx playwright install chromium`
- `VECTORS_DIR`: override vector directory
- `RESULTS_DIR`: override output directory

## Persisted Outputs

- Per-round JSON history: `benchmarks/canonical-json/results/history/round-<timestamp>-<round>.json`
- Latest snapshot: `benchmarks/canonical-json/results/latest.json`
- Latest report: `benchmarks/canonical-json/results/latest.md`
- Cross-round leaderboard: `benchmarks/canonical-json/results/leaderboard.md`

## Browser WASM Lane

The WASM lane compiles `benchmarks/canonical-json/wasm/module` to `wasm32-unknown-unknown` and benchmarks it inside Chromium using Playwright (`benchmarks/canonical-json/wasm/browser/run_browser_wasm_bench.mjs`).

## Regression Gate

Use the regression checker to compare a candidate round against a baseline file:

```bash
benchmarks/canonical-json/assert-no-regression.sh \
  --baseline benchmarks/canonical-json/results/history/round-...-baseline.json \
  --candidate benchmarks/canonical-json/results/latest.json \
  --max-regression-pct 5
```

The checker fails if any profile/language lane regresses beyond the configured percentage for `mean_ops_per_sec`.

## End-to-End QA Runner

For full test + benchmark gating in one command:

```bash
tools/qa/test-and-benchmark.sh --mode smoke
```

Use `--mode full` for the full benchmark iteration counts.
`full` mode expects a `baseline` round and uses a strict default threshold.
`smoke` mode uses lighter benchmark settings and a relaxed default threshold.
