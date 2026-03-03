#!/usr/bin/env bash
set -euo pipefail

PROJECT_PATH="${PROJECT_PATH:-.}"
OUT_DIR="${OUT_DIR:-.bardscan}"
FAIL_ON="${FAIL_ON:-high}"
FAIL_ON_UNKNOWN="${FAIL_ON_UNKNOWN:-true}"
UPDATE_DB="${UPDATE_DB:-true}"
FALLBACK_CALLS="${FALLBACK_CALLS:-true}"
LIST_FINDINGS="${LIST_FINDINGS:-medium-up}"
PRIVACY="${PRIVACY:-strict}"
EVIDENCE="${EVIDENCE:-none}"
BARDSCAN_BIN="${BARDSCAN_BIN:-}"

to_bool() {
  local normalized
  normalized="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$normalized" in
    true|1|yes|y|on) return 0 ;;
    false|0|no|n|off) return 1 ;;
    *)
      echo "Invalid boolean value: $1" >&2
      return 2
      ;;
  esac
}

resolve_bardscan_cmd() {
  if [[ -n "$BARDSCAN_BIN" ]]; then
    if [[ "$BARDSCAN_BIN" == "node "* ]]; then
      echo "$BARDSCAN_BIN"
      return 0
    fi
    echo "$BARDSCAN_BIN"
    return 0
  fi

  if command -v bardscan >/dev/null 2>&1; then
    echo "bardscan"
    return 0
  fi

  if [[ -f "./packages/cli/dist/index.js" ]]; then
    echo "node ./packages/cli/dist/index.js"
    return 0
  fi

  echo "Could not locate bardscan CLI. Set BARDSCAN_BIN or install/build bardscan first." >&2
  return 2
}

run_bardscan() {
  local cmd="$1"
  shift
  if [[ "$cmd" == node\ * ]]; then
    local script_path="${cmd#node }"
    node "$script_path" "$@"
    return 0
  fi

  "$cmd" "$@"
}

mkdir -p "$OUT_DIR"
BARDSCAN_CMD="$(resolve_bardscan_cmd)"

echo "Using bardscan command: $BARDSCAN_CMD"
echo "Project path: $PROJECT_PATH"
echo "Output directory: $OUT_DIR"

if to_bool "$UPDATE_DB"; then
  echo "Updating advisory cache..."
  db_args=(db update "$PROJECT_PATH" --out-dir "$OUT_DIR")
  if ! to_bool "$FALLBACK_CALLS"; then
    db_args+=(--no-fallback-calls)
  fi
  run_bardscan "$BARDSCAN_CMD" "${db_args[@]}"
fi

echo "Generating JSON + Markdown reports..."
report_args=(
  scan "$PROJECT_PATH"
  --format both
  --out-dir "$OUT_DIR"
  --offline
  --privacy "$PRIVACY"
  --evidence "$EVIDENCE"
  --fail-on none
  --list-findings "$LIST_FINDINGS"
  --findings-json "$OUT_DIR/findings.json"
)
run_bardscan "$BARDSCAN_CMD" "${report_args[@]}"

echo "Evaluating threshold and generating SARIF..."
threshold_args=(
  scan "$PROJECT_PATH"
  --format sarif
  --out-dir "$OUT_DIR"
  --offline
  --privacy "$PRIVACY"
  --evidence "$EVIDENCE"
  --fail-on "$FAIL_ON"
  --list-findings "$LIST_FINDINGS"
  --findings-json "$OUT_DIR/findings-threshold.json"
)
if to_bool "$FAIL_ON_UNKNOWN"; then
  threshold_args+=(--fail-on-unknown)
fi

set +e
run_bardscan "$BARDSCAN_CMD" "${threshold_args[@]}"
scan_exit=$?
set -e

if [[ "$scan_exit" -eq 2 ]]; then
  echo "bardscan returned tool error." >&2
  exit 2
fi

threshold_hit=false
if [[ "$scan_exit" -eq 1 ]]; then
  threshold_hit=true
fi

findings_count=0
if [[ -f "$OUT_DIR/findings-threshold.json" ]]; then
  findings_count="$(node -e "const fs=require('fs'); const data=JSON.parse(fs.readFileSync(process.argv[1],'utf8')); process.stdout.write(String(Array.isArray(data) ? data.length : 0));" "$OUT_DIR/findings-threshold.json")"
fi

summary_path="$OUT_DIR/ci-summary.json"
node -e '
const fs = require("fs");
const summary = {
  generatedAt: new Date().toISOString(),
  projectPath: process.argv[1],
  outDir: process.argv[2],
  failOn: process.argv[3],
  failOnUnknown: process.argv[4] === "true",
  thresholdHit: process.argv[5] === "true",
  findingsAtThreshold: Number(process.argv[6]),
  exitCode: Number(process.argv[7]),
  artifacts: {
    reportJson: `${process.argv[2]}/report.json`,
    reportMarkdown: `${process.argv[2]}/report.md`,
    reportSarif: `${process.argv[2]}/report.sarif`,
    findingsJson: `${process.argv[2]}/findings.json`,
    findingsThresholdJson: `${process.argv[2]}/findings-threshold.json`
  }
};
fs.writeFileSync(process.argv[8], JSON.stringify(summary, null, 2));
' "$PROJECT_PATH" "$OUT_DIR" "$FAIL_ON" "$FAIL_ON_UNKNOWN" "$threshold_hit" "$findings_count" "$scan_exit" "$summary_path"

echo "BARDSCAN_REPORT_JSON=$OUT_DIR/report.json"
echo "BARDSCAN_REPORT_MD=$OUT_DIR/report.md"
echo "BARDSCAN_REPORT_SARIF=$OUT_DIR/report.sarif"
echo "BARDSCAN_FINDINGS_JSON=$OUT_DIR/findings.json"
echo "BARDSCAN_FINDINGS_THRESHOLD_JSON=$OUT_DIR/findings-threshold.json"
echo "BARDSCAN_SUMMARY_JSON=$summary_path"
echo "BARDSCAN_THRESHOLD_HIT=$threshold_hit"
echo "BARDSCAN_FINDINGS_COUNT=$findings_count"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "threshold_hit=$threshold_hit"
    echo "findings_count=$findings_count"
    echo "summary_path=$summary_path"
  } >> "$GITHUB_OUTPUT"
fi

if [[ "$scan_exit" -eq 1 ]]; then
  exit 1
fi

exit 0
