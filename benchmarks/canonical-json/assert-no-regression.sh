#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

fail() {
  echo "error: $*" >&2
  exit 1
}

usage() {
  cat <<'USAGE'
Usage:
  assert-no-regression.sh --baseline <path> --candidate <path> [options]

Options:
  --max-regression-pct <number>   Allowed regression percentage (default: 5)
  --metric <name>                 Summary metric key (default: mean_ops_per_sec)
  --profiles <csv>                Restrict to profiles (e.g. base,stress)
  --languages <csv>               Restrict to languages (e.g. rust,julia,java)
  --allow-cross-host              Skip strict host identity check

Environment (equivalent defaults):
  MAX_REGRESSION_PCT=5
  METRIC=mean_ops_per_sec
  ALLOW_CROSS_HOST=0
USAGE
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

csv_contains() {
  local csv="$1"
  local needle="$2"
  [[ -z "$csv" ]] && return 0
  local item
  IFS=',' read -r -a arr <<< "$csv"
  for item in "${arr[@]}"; do
    if [[ "$item" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

BASELINE=""
CANDIDATE=""
MAX_REGRESSION_PCT="${MAX_REGRESSION_PCT:-5}"
METRIC="${METRIC:-mean_ops_per_sec}"
PROFILES_CSV=""
LANGUAGES_CSV=""
ALLOW_CROSS_HOST="${ALLOW_CROSS_HOST:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --baseline)
      [[ $# -ge 2 ]] || fail "missing value for --baseline"
      BASELINE="$2"
      shift 2
      ;;
    --candidate)
      [[ $# -ge 2 ]] || fail "missing value for --candidate"
      CANDIDATE="$2"
      shift 2
      ;;
    --max-regression-pct)
      [[ $# -ge 2 ]] || fail "missing value for --max-regression-pct"
      MAX_REGRESSION_PCT="$2"
      shift 2
      ;;
    --metric)
      [[ $# -ge 2 ]] || fail "missing value for --metric"
      METRIC="$2"
      shift 2
      ;;
    --profiles)
      [[ $# -ge 2 ]] || fail "missing value for --profiles"
      PROFILES_CSV="$2"
      shift 2
      ;;
    --languages)
      [[ $# -ge 2 ]] || fail "missing value for --languages"
      LANGUAGES_CSV="$2"
      shift 2
      ;;
    --allow-cross-host)
      ALLOW_CROSS_HOST="1"
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

require_cmd jq
require_cmd awk

[[ -n "$BASELINE" ]] || fail "missing --baseline"
[[ -n "$CANDIDATE" ]] || fail "missing --candidate"
[[ -f "$BASELINE" ]] || fail "baseline file not found: $BASELINE"
[[ -f "$CANDIDATE" ]] || fail "candidate file not found: $CANDIDATE"

jq -e . "$BASELINE" >/dev/null || fail "invalid JSON: $BASELINE"
jq -e . "$CANDIDATE" >/dev/null || fail "invalid JSON: $CANDIDATE"

if [[ "$ALLOW_CROSS_HOST" != "1" ]]; then
  base_host="$(jq -r '.host | "\(.os)|\(.arch)|\(.cpu)"' "$BASELINE")"
  cand_host="$(jq -r '.host | "\(.os)|\(.arch)|\(.cpu)"' "$CANDIDATE")"
  [[ "$base_host" == "$cand_host" ]] || fail "host mismatch: baseline=$base_host candidate=$cand_host (use --allow-cross-host to override)"
fi

if ! jq -e '.checksums | all(.match)' "$CANDIDATE" >/dev/null; then
  jq '.checksums' "$CANDIDATE" >&2
  fail "candidate benchmark checksums are not consistent across lanes"
fi

echo "Comparing metric '$METRIC' against baseline (max regression ${MAX_REGRESSION_PCT}%)"
printf '%-10s %-12s %14s %14s %12s %s\n' "PROFILE" "LANGUAGE" "BASELINE" "CANDIDATE" "DELTA(%)" "STATUS"

keys="$(jq -r '.results[] | "\(.profile)|\(.language)"' "$BASELINE" | sort -u)"
[[ -n "$keys" ]] || fail "no results found in baseline"

failures=0
while IFS= read -r key; do
  [[ -n "$key" ]] || continue
  profile="${key%%|*}"
  language="${key##*|}"

  if ! csv_contains "$PROFILES_CSV" "$profile"; then
    continue
  fi
  if ! csv_contains "$LANGUAGES_CSV" "$language"; then
    continue
  fi

  baseline_value="$(jq -r --arg p "$profile" --arg l "$language" --arg m "$METRIC" '.results[] | select(.profile == $p and .language == $l) | .summary[$m]' "$BASELINE" | head -n1)"
  candidate_value="$(jq -r --arg p "$profile" --arg l "$language" --arg m "$METRIC" '.results[] | select(.profile == $p and .language == $l) | .summary[$m]' "$CANDIDATE" | head -n1)"

  [[ -n "$baseline_value" && "$baseline_value" != "null" ]] || fail "missing baseline metric for $profile/$language"
  [[ -n "$candidate_value" && "$candidate_value" != "null" ]] || fail "missing candidate metric for $profile/$language"

  delta_pct="$(awk -v base="$baseline_value" -v cand="$candidate_value" 'BEGIN { if (base == 0) { print "0.000"; } else { printf "%.3f", ((cand - base) / base) * 100.0; } }')"

  status="OK"
  is_regression="$(awk -v d="$delta_pct" -v t="$MAX_REGRESSION_PCT" 'BEGIN { if (d < (-1.0 * t)) print "1"; else print "0"; }')"
  if [[ "$is_regression" == "1" ]]; then
    status="REGRESSION"
    failures=$((failures + 1))
  fi

  printf '%-10s %-12s %14.1f %14.1f %12s %s\n' \
    "$profile" "$language" "$baseline_value" "$candidate_value" "$delta_pct" "$status"
done <<< "$keys"

if [[ "$failures" -gt 0 ]]; then
  fail "detected $failures regression(s) beyond ${MAX_REGRESSION_PCT}%"
fi

echo "Regression check passed."
