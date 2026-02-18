#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

ROUND="${ROUND:-baseline}"
RUNS="${RUNS:-7}"

BASE_ITERATIONS="${BASE_ITERATIONS:-50000}"
BASE_WARMUP="${BASE_WARMUP:-5000}"
STRESS_ITERATIONS="${STRESS_ITERATIONS:-5000}"
STRESS_WARMUP="${STRESS_WARMUP:-500}"

ENABLE_WASM_BROWSER="${ENABLE_WASM_BROWSER:-1}"
ENABLE_JAVA_LANE="${ENABLE_JAVA_LANE:-auto}"
ENSURE_PLAYWRIGHT_DEPS="${ENSURE_PLAYWRIGHT_DEPS:-0}"
ENSURE_PLAYWRIGHT_BROWSER="${ENSURE_PLAYWRIGHT_BROWSER:-0}"

VECTORS_DIR="${VECTORS_DIR:-$ROOT/examples/contracts/canon_vectors}"
RESULTS_DIR="${RESULTS_DIR:-$ROOT/benchmarks/canonical-json/results}"
HISTORY_DIR="$RESULTS_DIR/history"

WASM_MANIFEST="$ROOT/benchmarks/canonical-json/wasm/module/Cargo.toml"
WASM_MODULE_PATH="$ROOT/benchmarks/canonical-json/wasm/module/target/wasm32-unknown-unknown/release/rulia_canon_bench_wasm_module.wasm"
WASM_BROWSER_RUNNER="$ROOT/benchmarks/canonical-json/wasm/browser/run_browser_wasm_bench.mjs"
PLAYWRIGHT_PROJECT_DIR="$ROOT/examples/tests/playwright"
RUN_LOCK_DIR=""

fail() {
  echo "error: $*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

acquire_run_lock() {
  local lock_dir="$RESULTS_DIR/.benchmark-run.lock"

  if mkdir "$lock_dir" 2>/dev/null; then
    printf '%s\n' "$$" > "$lock_dir/pid"
    RUN_LOCK_DIR="$lock_dir"
    return
  fi

  local holder_pid=""
  if [[ -f "$lock_dir/pid" ]]; then
    holder_pid="$(cat "$lock_dir/pid" 2>/dev/null || true)"
  fi

  if [[ -n "$holder_pid" ]] && kill -0 "$holder_pid" 2>/dev/null; then
    fail "another benchmark run is already active (pid=$holder_pid); wait for it to finish"
  fi

  fail "benchmark lock exists at $lock_dir; remove the stale lock directory and retry"
}

release_run_lock() {
  if [[ -n "$RUN_LOCK_DIR" ]]; then
    rm -rf "$RUN_LOCK_DIR"
    RUN_LOCK_DIR=""
  fi
}

extract_json_line() {
  awk '/^\{.*\}$/ {line=$0} END {if (line == "") {exit 1} print line}'
}

round_slug() {
  local raw="$1"
  local slug
  slug="$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9._-' '-')"
  slug="${slug#-}"
  slug="${slug%-}"
  [[ -n "$slug" ]] || slug="baseline"
  printf '%s\n' "$slug"
}

iterations_for_profile() {
  case "$1" in
    base) printf '%s\n' "$BASE_ITERATIONS" ;;
    stress) printf '%s\n' "$STRESS_ITERATIONS" ;;
    *) fail "unsupported profile: $1" ;;
  esac
}

warmup_for_profile() {
  case "$1" in
    base) printf '%s\n' "$BASE_WARMUP" ;;
    stress) printf '%s\n' "$STRESS_WARMUP" ;;
    *) fail "unsupported profile: $1" ;;
  esac
}

run_rust() {
  local profile="$1"
  local iterations="$2"
  local warmup="$3"

  cargo run --quiet --release \
    --manifest-path "$ROOT/benchmarks/canonical-json/rust/Cargo.toml" \
    -- \
    --vectors-dir "$VECTORS_DIR" \
    --profile "$profile" \
    --iterations "$iterations" \
    --warmup "$warmup"
}

run_julia() {
  local profile="$1"
  local iterations="$2"
  local warmup="$3"

  julia --project="$ROOT/examples/services/workflow-host-julia" \
    --threads auto \
    "$ROOT/benchmarks/canonical-json/julia/canon_bench.jl" \
    --vectors-dir "$VECTORS_DIR" \
    --profile "$profile" \
    --iterations "$iterations" \
    --warmup "$warmup"
}

run_java() {
  local profile="$1"
  local iterations="$2"
  local warmup="$3"

  (
    cd "$ROOT/examples/services/java-services/audit-ledger"
    gradle --no-daemon -q canonBench \
      -PbenchArgs="--vectors-dir $VECTORS_DIR --profile $profile --iterations $iterations --warmup $warmup"
  )
}

java_bench_supported() {
  (
    cd "$ROOT/examples/services/java-services/audit-ledger"
    gradle -q tasks --all 2>/dev/null | awk '/^canonBench[[:space:]]/ {found=1} END {exit(found?0:1)}'
  )
}

run_wasm_browser() {
  local profile="$1"
  local iterations="$2"
  local warmup="$3"

  (
    cd "$PLAYWRIGHT_PROJECT_DIR"
    node "$WASM_BROWSER_RUNNER" \
      --wasm-path "$WASM_MODULE_PATH" \
      --profile "$profile" \
      --iterations "$iterations" \
      --warmup "$warmup"
  )
}

ensure_playwright_deps() {
  if [[ "$ENSURE_PLAYWRIGHT_DEPS" == "1" ]]; then
    (cd "$PLAYWRIGHT_PROJECT_DIR" && npm ci)
  fi

  if [[ ! -d "$PLAYWRIGHT_PROJECT_DIR/node_modules/playwright" ]]; then
    fail "playwright dependency missing in $PLAYWRIGHT_PROJECT_DIR. Run: (cd $PLAYWRIGHT_PROJECT_DIR && npm ci)"
  fi

  if [[ "$ENSURE_PLAYWRIGHT_BROWSER" == "1" ]]; then
    (cd "$PLAYWRIGHT_PROJECT_DIR" && npx playwright install chromium)
  fi
}

build_wasm_module() {
  cargo build --release --target wasm32-unknown-unknown --manifest-path "$WASM_MANIFEST"
  [[ -f "$WASM_MODULE_PATH" ]] || fail "missing wasm output: $WASM_MODULE_PATH"
}

run_series() {
  local language="$1"
  local profile="$2"
  local iterations="$3"
  local warmup="$4"
  local runner="$5"

  for run in $(seq 1 "$RUNS"); do
    echo "[$profile][$language] run $run/$RUNS" >&2

    local raw
    if ! raw="$($runner "$profile" "$iterations" "$warmup" 2>&1)"; then
      echo "$raw" >&2
      fail "$language benchmark failed for profile=$profile"
    fi

    local json_line
    if ! json_line="$(printf '%s\n' "$raw" | extract_json_line)"; then
      echo "$raw" >&2
      fail "failed to parse JSON output from $language benchmark (profile=$profile)"
    fi

    echo "$json_line" >> "$ALL_RESULTS_FILE"
  done
}

require_cmd cargo
require_cmd rustc
require_cmd julia
require_cmd jq
require_cmd java
require_cmd gradle
if [[ "$ENABLE_WASM_BROWSER" == "1" ]]; then
  require_cmd node
  require_cmd npm
fi

mkdir -p "$RESULTS_DIR" "$HISTORY_DIR"
acquire_run_lock

if [[ "$ENABLE_WASM_BROWSER" == "1" ]]; then
  ensure_playwright_deps
  build_wasm_module
fi

TMP_DIR="$(mktemp -d)"
trap 'release_run_lock; rm -rf "$TMP_DIR"' EXIT
ALL_RESULTS_FILE="$TMP_DIR/all.jsonl"
: > "$ALL_RESULTS_FILE"

PROFILES=(base stress)
LANGUAGES=(rust julia)

case "$ENABLE_JAVA_LANE" in
  1)
    if java_bench_supported; then
      LANGUAGES+=(java)
    else
      fail "java lane requested but canonBench task is unavailable in examples/services/java-services/audit-ledger"
    fi
    ;;
  0)
    ;;
  auto)
    if java_bench_supported; then
      LANGUAGES+=(java)
    else
      echo "warning: skipping java lane (canonBench task unavailable)" >&2
    fi
    ;;
  *)
    fail "ENABLE_JAVA_LANE must be one of: 0, 1, auto"
    ;;
esac

if [[ "$ENABLE_WASM_BROWSER" == "1" ]]; then
  LANGUAGES+=(wasm-browser)
fi

for profile in "${PROFILES[@]}"; do
  iterations="$(iterations_for_profile "$profile")"
  warmup="$(warmup_for_profile "$profile")"

  for language in "${LANGUAGES[@]}"; do
    case "$language" in
      rust) run_series "$language" "$profile" "$iterations" "$warmup" run_rust ;;
      julia) run_series "$language" "$profile" "$iterations" "$warmup" run_julia ;;
      java) run_series "$language" "$profile" "$iterations" "$warmup" run_java ;;
      wasm-browser) run_series "$language" "$profile" "$iterations" "$warmup" run_wasm_browser ;;
      *) fail "unsupported language lane: $language" ;;
    esac
  done
done

ALL_RESULTS="$(jq -s '.' "$ALL_RESULTS_FILE")"

TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ROUND_SLUG="$(round_slug "$ROUND")"
RESULT_FILE="$HISTORY_DIR/round-$STAMP-$ROUND_SLUG.json"
LATEST_JSON="$RESULTS_DIR/latest.json"
LATEST_MD="$RESULTS_DIR/latest.md"
LEADERBOARD_MD="$RESULTS_DIR/leaderboard.md"

CPU_MODEL="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)"
JAVA_VERSION="$(java -version 2>&1 | head -n 1)"
RUST_VERSION="$(rustc --version)"
JULIA_VERSION="$(julia --version)"
GRADLE_VERSION="$(gradle -v | awk '/^Gradle / {print $2; exit}')"

jq -n \
  --arg timestamp "$TIMESTAMP" \
  --arg round "$ROUND" \
  --arg os "$(uname -s)" \
  --arg arch "$(uname -m)" \
  --arg kernel "$(uname -r)" \
  --arg cpu "$CPU_MODEL" \
  --arg rust_version "$RUST_VERSION" \
  --arg julia_version "$JULIA_VERSION" \
  --arg java_version "$JAVA_VERSION" \
  --arg gradle_version "$GRADLE_VERSION" \
  --arg vectors_dir "$VECTORS_DIR" \
  --arg runs "$RUNS" \
  --arg base_iterations "$BASE_ITERATIONS" \
  --arg base_warmup "$BASE_WARMUP" \
  --arg stress_iterations "$STRESS_ITERATIONS" \
  --arg stress_warmup "$STRESS_WARMUP" \
  --arg wasm_enabled "$ENABLE_WASM_BROWSER" \
  --arg java_lane "$ENABLE_JAVA_LANE" \
  --argjson all "$ALL_RESULTS" \
  '
  def median:
    sort as $s
    | ($s | length) as $n
    | if $n == 0 then 0
      elif ($n % 2) == 1 then $s[$n / 2]
      else (($s[$n / 2 - 1] + $s[$n / 2]) / 2)
      end;

  def stats($rows):
    ($rows | map(.ops_per_sec)) as $ops
    | ($rows | map(.elapsed_ns / 1000000.0)) as $elapsed_ms
    | {
        runs: ($rows | length),
        vectors: ($rows[0].vectors),
        iterations: ($rows[0].iterations),
        mean_ops_per_sec: (if ($ops | length) == 0 then 0 else ($ops | add) / ($ops | length) end),
        median_ops_per_sec: ($ops | median),
        min_ops_per_sec: (if ($ops | length) == 0 then 0 else ($ops | min) end),
        max_ops_per_sec: (if ($ops | length) == 0 then 0 else ($ops | max) end),
        stddev_ops_per_sec: (
          if ($ops | length) <= 1 then 0
          else (
            (($ops | add) / ($ops | length)) as $mean
            | ([ $ops[] | ((. - $mean) * (. - $mean)) ] | add / (($ops | length) - 1) | sqrt)
          )
          end
        ),
        mean_elapsed_ms: (if ($elapsed_ms | length) == 0 then 0 else ($elapsed_ms | add) / ($elapsed_ms | length) end),
        median_elapsed_ms: ($elapsed_ms | median)
      };

  def grouped($rows):
    $rows
    | sort_by(.profile, .language)
    | group_by(.profile, .language)
    | map({
        profile: .[0].profile,
        language: .[0].language,
        runs: .,
        summary: stats(.),
        checksums_unique: (map(.checksum) | unique)
      });

  def checksum_status($entries):
    $entries
    | sort_by(.profile)
    | group_by(.profile)
    | map({
        profile: .[0].profile,
        by_language: (map({key: .language, value: .checksums_unique}) | from_entries),
        unique_checksums: (map(.checksums_unique[]) | unique),
        match: ((map(.checksums_unique | length == 1) | all) and ((map(.checksums_unique[]) | unique | length) == 1))
      });

  def rankings($entries):
    $entries
    | sort_by(.profile)
    | group_by(.profile)
    | map({
        profile: .[0].profile,
        ranking: (
          sort_by(.summary.mean_ops_per_sec)
          | reverse
          | map({
              language,
              mean_ops_per_sec: .summary.mean_ops_per_sec,
              median_ops_per_sec: .summary.median_ops_per_sec,
              mean_elapsed_ms: .summary.mean_elapsed_ms,
              stddev_ops_per_sec: .summary.stddev_ops_per_sec,
              vectors: .summary.vectors,
              iterations: .summary.iterations
            })
        )
      });

  (grouped($all)) as $entries
  | {
      timestamp_utc: $timestamp,
      round: $round,
      host: {
        os: $os,
        arch: $arch,
        kernel: $kernel,
        cpu: $cpu
      },
      toolchain: {
        rust: $rust_version,
        julia: $julia_version,
        java: $java_version,
        gradle: $gradle_version
      },
      settings: {
        runs: ($runs | tonumber),
        vectors_dir: $vectors_dir,
        profiles: {
          base: {
            iterations: ($base_iterations | tonumber),
            warmup: ($base_warmup | tonumber)
          },
          stress: {
            iterations: ($stress_iterations | tonumber),
            warmup: ($stress_warmup | tonumber)
          }
        },
        wasm_browser_enabled: ($wasm_enabled == "1"),
        java_lane: $java_lane
      },
      results: $entries,
      checksums: checksum_status($entries),
      rankings: rankings($entries)
    }
  ' > "$RESULT_FILE"

if ! jq -e '.checksums | all(.match)' "$RESULT_FILE" >/dev/null; then
  jq '.checksums' "$RESULT_FILE" >&2
  fail "cross-language checksum mismatch detected"
fi

cp "$RESULT_FILE" "$LATEST_JSON"

jq -r '
  def round1: ((. * 10.0) | round / 10.0);
  def round2: ((. * 100.0) | round / 100.0);

  . as $doc
  | [
      "# Language Optimization Competition",
      "",
      "- timestamp: \($doc.timestamp_utc)",
      "- round: \($doc.round)",
      "- host: \($doc.host.os) \($doc.host.arch) (\($doc.host.cpu))",
      "- runs per lane: \($doc.settings.runs)",
      "- profiles: base(iter=\($doc.settings.profiles.base.iterations), warmup=\($doc.settings.profiles.base.warmup)), stress(iter=\($doc.settings.profiles.stress.iterations), warmup=\($doc.settings.profiles.stress.warmup))",
      ""
    ]
    + (
      $doc.rankings
      | map(
          [
            "## Profile: \(.profile)",
            "",
            "| Rank | Language | Mean ops/s | Median ops/s | Mean elapsed (ms) | Stddev ops/s |",
            "| ---: | --- | ---: | ---: | ---: | ---: |"
          ]
          + (
            .ranking
            | to_entries
            | map("| \(.key + 1) | \(.value.language) | \(.value.mean_ops_per_sec | round1) | \(.value.median_ops_per_sec | round1) | \(.value.mean_elapsed_ms | round2) | \(.value.stddev_ops_per_sec | round1) |")
          )
          + [""]
        )
      | add
    )
    + (
      [
        "## Checksum Integrity",
        ""
      ]
      + (
        $doc.checksums
        | map("- \(.profile): \(if .match then "MATCH" else "MISMATCH" end), checksum=\(.unique_checksums | join(","))")
      )
    )
    | join("\n")
' "$RESULT_FILE" > "$LATEST_MD"

shopt -s nullglob
HISTORY_FILES=("$HISTORY_DIR"/round-*.json)
shopt -u nullglob

if [[ ${#HISTORY_FILES[@]} -gt 0 ]]; then
  jq -r -s '
    def round1: ((. * 10.0) | round / 10.0);

    [ .[] as $doc
      | $doc.results[]
      | {
          profile,
          language,
          round: $doc.round,
          timestamp: $doc.timestamp_utc,
          mean_ops_per_sec: .summary.mean_ops_per_sec,
          median_ops_per_sec: .summary.median_ops_per_sec
        }
    ] as $rows
    | ($rows | sort_by(.profile, .language) | group_by(.profile, .language) | map(max_by(.mean_ops_per_sec))) as $best
    | [
        "# Competition Leaderboard",
        "",
        "| Profile | Language | Best mean ops/s | Median ops/s | Round | Timestamp |",
        "| --- | --- | ---: | ---: | --- | --- |"
      ]
      + (
        $best
        | sort_by(.profile, .language)
        | map("| \(.profile) | \(.language) | \(.mean_ops_per_sec | round1) | \(.median_ops_per_sec | round1) | \(.round) | \(.timestamp) |")
      )
      | join("\n")
  ' "${HISTORY_FILES[@]}" > "$LEADERBOARD_MD"
fi

cat <<SUMMARY
benchmark competition run complete
round: $ROUND
result json: $RESULT_FILE
latest json: $LATEST_JSON
latest md: $LATEST_MD
leaderboard md: $LEADERBOARD_MD
SUMMARY
