#!/usr/bin/env bash
# run_all.sh - run the WAF efficacy corpus against every configured front-end in
# sequence, then print the side-by-side --compare table.
#
# Edit targets.conf (copy from targets.conf.example) to set the temp URL for each
# of: safeline, direct, cloudflare, fastly. Any config with an empty *_TARGET is skipped.
#
#   ./run_all.sh                 # dry-run: show the plan for each configured front-end
#   ./run_all.sh --run           # actually send, then print the comparison
#   ./run_all.sh --run myconf     # use a different config file
#
# Safe by default: sends nothing until --run. See README.md for the safety rationale.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RUNFLAG=""
if [[ "${1:-}" == "--run" ]]; then RUNFLAG="--run"; shift; fi
CONF="${1:-$HERE/targets.conf}"

if [[ ! -f "$CONF" ]]; then
  echo "No config file at $CONF" >&2
  echo "Copy targets.conf.example to targets.conf and fill in the temp URLs." >&2
  exit 1
fi
# shellcheck disable=SC1090
source "$CONF"

RUNTAG="${RUNTAG:-waf-$(date +%Y%m%d)}"
RATE="${RATE:-0.3}"
OUT="$HERE/out"
mkdir -p "$OUT"

run_one() {           # $1=config label  $2=target  $3=extra opts
  local cfg="$1" target="$2" opts="$3"
  [[ -z "$target" ]] && { echo ">> skip $cfg (no target set)"; return; }
  echo
  echo "======================================================================"
  echo ">> $cfg  ->  $target   ${opts}"
  echo "======================================================================"
  # shellcheck disable=SC2086
  python3 "$HERE/waf_efficacy_test.py" \
      --config "$cfg" --target "$target" $opts \
      --rate "$RATE" --runid "$RUNTAG" --out "$OUT" $RUNFLAG
}

run_one safeline   "${SAFELINE_TARGET:-}"   "${SAFELINE_OPTS:-}"
run_one direct     "${DIRECT_TARGET:-}"     "${DIRECT_OPTS:-}"
run_one cloudflare "${CLOUDFLARE_TARGET:-}" "${CLOUDFLARE_OPTS:-}"
run_one fastly     "${FASTLY_TARGET:-}"     "${FASTLY_OPTS:-}"

if [[ -z "$RUNFLAG" ]]; then
  echo
  echo "DRY-RUN only. Re-run with:  ./run_all.sh --run   to send and compare."
  exit 0
fi

echo
echo "======================================================================"
echo ">> COMPARISON  (runtag=$RUNTAG)"
echo "======================================================================"
shopt -s nullglob
files=( "$OUT/${RUNTAG}_"*.json )
if (( ${#files[@]} == 0 )); then
  echo "No result files found for runtag $RUNTAG." >&2
  exit 1
fi
python3 "$HERE/waf_efficacy_test.py" --compare "${files[@]}"
