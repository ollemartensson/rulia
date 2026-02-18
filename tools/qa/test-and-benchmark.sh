#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

fail() {
  echo "error: $*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

usage() {
  cat <<'USAGE'
Usage:
  tools/qa/test-and-benchmark.sh [--mode smoke|full] [--skip-tests] [--skip-benchmarks]

Options:
  --mode smoke|full          Default: smoke
  --skip-tests               Skip test matrix
  --skip-benchmarks          Skip benchmark run + regression gate
  -h, --help                 Show help

Environment:
  BENCH_BASELINE_ROUND       Baseline round label for regression comparison (overrides auto baseline selection)
  BENCH_MAX_REGRESSION_PCT   Allowed perf drop percentage (default: 5)
  BENCH_REQUIRE_BASELINE     1 to fail if baseline round is missing (default: 0 for smoke, 1 for full)
  BENCH_ENABLE_JAVA_LANE     1 to force java lane, 0 to skip, auto to detect (default: auto)
  BENCH_ENABLE_WASM_BROWSER  1 to include wasm-browser lane (default: 0)
USAGE
}

MODE="smoke"
SKIP_TESTS=0
SKIP_BENCHMARKS=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      [[ $# -ge 2 ]] || fail "missing value for --mode"
      MODE="$2"
      shift 2
      ;;
    --skip-tests)
      SKIP_TESTS=1
      shift
      ;;
    --skip-benchmarks)
      SKIP_BENCHMARKS=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

[[ "$MODE" == "smoke" || "$MODE" == "full" ]] || fail "mode must be smoke or full"

require_cmd jq
require_cmd cargo
require_cmd rustc
require_cmd java
require_cmd gradle
require_cmd julia
require_cmd bash

run_rust_tests() {
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  ln -s "$ROOT/engine/rulia" "$tmp/rulia"

  cat > "$tmp/Cargo.toml" <<'EOF'
[workspace]
members = ["rulia"]
resolver = "2"

[workspace.package]
version = "0.1.0"
edition = "2021"
rust-version = "1.82"
license = "MIT"
repository = "https://example.invalid/rulia"
keywords = ["rulia"]
categories = ["encoding"]

[workspace.dependencies]
thiserror = "2"
sha2 = "0.10"
hex = "0.4"
blake3 = "1"
criterion = "0.5"
serde = { version = "1", features = ["derive"] }
serde_bytes = "0.11"
EOF

  if [[ "$MODE" == "smoke" ]]; then
    cargo test --manifest-path "$tmp/Cargo.toml" -p rulia --test text --test references_and_namespaces
  else
    cargo test --manifest-path "$tmp/Cargo.toml" -p rulia --all-targets
  fi
}

run_jvm_tests() {
  (cd "$ROOT/sdk/jvm" && ./gradlew :rulia-jvm:test --rerun-tasks)
}

run_julia_tests() {
  (
    cd "$ROOT/sdk/julia/Rulia.jl"
    julia --project=. -e 'using Pkg; Pkg.test()'
    rm -f Manifest.toml
  )
}

run_benchmarks() {
  local bench_runs base_iter base_warmup stress_iter stress_warmup
  local wasm_browser java_lane
  local baseline_round baseline_file candidate_file threshold require_baseline previous_latest
  local candidate_languages

  if [[ "$MODE" == "smoke" ]]; then
    bench_runs=1
    base_iter=5000
    base_warmup=500
    stress_iter=500
    stress_warmup=50
  else
    bench_runs=7
    base_iter=50000
    base_warmup=5000
    stress_iter=5000
    stress_warmup=500
  fi

  wasm_browser="${BENCH_ENABLE_WASM_BROWSER:-0}"
  java_lane="${BENCH_ENABLE_JAVA_LANE:-auto}"
  previous_latest="$(ls -1 "$ROOT/benchmarks/canonical-json/results/history"/round-*.json 2>/dev/null | sort | tail -n1 || true)"

  ROUND="qa-${MODE}-$(date -u +%Y%m%dT%H%M%SZ)" \
  RUNS="$bench_runs" \
  BASE_ITERATIONS="$base_iter" \
  BASE_WARMUP="$base_warmup" \
  STRESS_ITERATIONS="$stress_iter" \
  STRESS_WARMUP="$stress_warmup" \
  ENABLE_JAVA_LANE="$java_lane" \
  ENABLE_WASM_BROWSER="$wasm_browser" \
  "$ROOT/benchmarks/canonical-json/run.sh"

  baseline_round="${BENCH_BASELINE_ROUND:-}"

  if [[ -n "${BENCH_MAX_REGRESSION_PCT:-}" ]]; then
    threshold="${BENCH_MAX_REGRESSION_PCT}"
  elif [[ "$MODE" == "smoke" ]]; then
    threshold="35"
  else
    threshold="5"
  fi

  if [[ -n "${BENCH_REQUIRE_BASELINE:-}" ]]; then
    require_baseline="${BENCH_REQUIRE_BASELINE}"
  elif [[ "$MODE" == "smoke" ]]; then
    require_baseline="0"
  else
    require_baseline="1"
  fi

  if [[ -n "$baseline_round" ]]; then
    baseline_file="$(ls -1 "$ROOT/benchmarks/canonical-json/results/history"/round-*-"$baseline_round".json 2>/dev/null | sort | tail -n1 || true)"
  else
    baseline_file="$previous_latest"
  fi
  candidate_file="$ROOT/benchmarks/canonical-json/results/latest.json"

  [[ -f "$candidate_file" ]] || fail "missing candidate benchmark file: $candidate_file"
  if [[ -z "$baseline_file" ]]; then
    if [[ "$require_baseline" == "1" ]]; then
      if [[ -n "$baseline_round" ]]; then
        fail "no baseline benchmark file found for round label '$baseline_round'"
      fi
      fail "no prior benchmark snapshot found for baseline comparison"
    fi
    if [[ -n "$baseline_round" ]]; then
      echo "warning: no baseline benchmark found for '$baseline_round'; skipping regression comparison" >&2
    else
      echo "warning: no prior benchmark snapshot found; skipping regression comparison" >&2
    fi
    return
  fi

  candidate_languages="$(jq -r '[.results[].language] | unique | join(",")' "$candidate_file")"
  [[ -n "$candidate_languages" ]] || fail "candidate benchmark output has no language results"

  MAX_REGRESSION_PCT="$threshold" \
  "$ROOT/benchmarks/canonical-json/assert-no-regression.sh" \
    --baseline "$baseline_file" \
    --candidate "$candidate_file" \
    --languages "$candidate_languages" \
    --max-regression-pct "$threshold"
}

echo "QA mode: $MODE"
echo "repo: $ROOT"

if [[ "$SKIP_TESTS" == "0" ]]; then
  echo "==> Running Rust tests"
  run_rust_tests

  echo "==> Running JVM tests"
  run_jvm_tests

  echo "==> Running Julia tests"
  run_julia_tests
fi

if [[ "$SKIP_BENCHMARKS" == "0" ]]; then
  echo "==> Running benchmark round + regression gate"
  run_benchmarks
fi

echo "QA suite completed successfully."
