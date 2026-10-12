#!/usr/bin/env bash
# waf_efficacy_check.sh - post-apply gate for the Fastly WAF trial.
#
# Runs the benign WAF efficacy replay harness against the Fastly-fronted trial URL and FAILS (non-zero) unless the
# Fastly posture is at least as good as your incumbent WAF's baseline AND does not block any legitimate control
# request. Run this in log->grade and before flipping ngwaf_mode to block / ramping edge traffic.
#
#   usage: waf_efficacy_check.sh <trial-url> [--host <vhost>] [--baseline-bypass <pct>] [--harness <dir>]
#   e.g.:  waf_efficacy_check.sh https://trial.example.com --host origin.example.com
#
# Defaults:
#   --harness         $WAF_EFFICACY_DIR or --harness (path to the benign replay harness dir)
#   --baseline-bypass 0.2   (your incumbent WAF baseline: the %% of attack probes it lets through)
#
# Exit: 0 = Fastly bypass% <= baseline AND 0 control false positives. Non-zero otherwise (prints why).
set -euo pipefail

TARGET="${1:-}"; shift || true
HOST=""
BASELINE_BYPASS="0.2"
HARNESS="${WAF_EFFICACY_DIR:-$(cd "$(dirname "$0")/.." && pwd)/waf_efficacy_test}"
EXTRA=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --baseline-bypass) BASELINE_BYPASS="$2"; shift 2 ;;
    --harness) HARNESS="$2"; shift 2 ;;
    *) EXTRA+=("$1"); shift ;;
  esac
done

if [[ -z "$TARGET" ]]; then echo "usage: waf_efficacy_check.sh <trial-url> [--host <vhost>] [--baseline-bypass <pct>] [--harness <dir>]" >&2; exit 2; fi
if [[ ! -f "$HARNESS/waf_efficacy_test.py" ]]; then echo "harness not found at $HARNESS (set --harness or \$WAF_EFFICACY_DIR)" >&2; exit 2; fi

RUNID="fastly-gate-$(date +%s)"
OUT="$HARNESS/out"
HOSTARG=(); [[ -n "$HOST" ]] && HOSTARG=(--host "$HOST")

echo ">> replaying attack corpus against $TARGET (config=fastly, runid=$RUNID)"
python3 "$HARNESS/waf_efficacy_test.py" \
  --target "$TARGET" --config fastly --run --runid "$RUNID" --out "$OUT" \
  "${HOSTARG[@]}" "${EXTRA[@]}"

RESULT="$OUT/${RUNID}_fastly.json"
[[ -f "$RESULT" ]] || { echo "no result file at $RESULT" >&2; exit 2; }

# Parse: traffic-weighted bypass% is not in the JSON, so compute passed-the-WAF% and control false positives here.
python3 - "$RESULT" "$BASELINE_BYPASS" <<'PY'
import json, sys
res = json.load(open(sys.argv[1]))["results"]
baseline = float(sys.argv[2])
atk = [r for r in res if r["expect"] == "block" and r["verdict"] != "ERROR"]
ctl = [r for r in res if r["expect"] == "pass" and r["verdict"] != "ERROR"]
passed = [r for r in atk if r["verdict"] == "PASSED"]
fp = [r for r in ctl if r["verdict"] in ("BLOCKED", "CHALLENGED")]
bypass_pct = 100.0 * len(passed) / len(atk) if atk else 0.0
print(f"attack probes       : {len(atk)}")
print(f"PASSED the WAF      : {len(passed)}  ({bypass_pct:.1f}%)   baseline <= {baseline}%")
print(f"control false pos   : {len(fp)}/{len(ctl)}")
if passed:
    print("  bypassed categories:", ", ".join(sorted({r['category'] for r in passed})))
fail = []
if bypass_pct > baseline: fail.append(f"bypass {bypass_pct:.1f}% > baseline {baseline}%")
if fp: fail.append(f"{len(fp)} control false positive(s)")
if fail:
    print("GATE FAIL:", "; ".join(fail)); sys.exit(1)
print("GATE PASS: Fastly posture meets or beats the baseline with no false positives.")
PY
