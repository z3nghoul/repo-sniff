#!/usr/bin/env bash
# Scans a list of popular honest repositories with a release build and writes
# one raw report per repository plus a results.tsv summary.
#
# usage: scripts/benchmark.sh [OUT_DIR]
#
# Needs: cargo, git, a network connection and GNU `timeout`. Each repository
# gets TIMEOUT seconds (default 300) including the clone; a repository that
# takes longer is recorded as "timeout" and skipped.
set -u

OUT="${1:-bench-out}"
TIMEOUT="${TIMEOUT:-300}"
REPOS=(
  BurntSushi/ripgrep
  rust-lang/cargo
  psf/requests
  pallets/flask
  pypa/pip
  expressjs/express
  microsoft/vscode
  git/git
  python/cpython
  microsoft/terminal
)

cd "$(dirname "$0")/.." || exit 1
cargo build --release -q || exit 1
BIN="$PWD/target/release/repo-sniff"
mkdir -p "$OUT"

printf 'repo\thead\tresult\texit\tcritical\thigh\tmedium\tlow\tinfo\tskipped\tseconds\tscan\n' >"$OUT/results.tsv"

for repo in "${REPOS[@]}"; do
  name="${repo//\//__}"
  url="https://github.com/$repo"
  head="$(git ls-remote "$url" HEAD 2>/dev/null | cut -c1-12)"
  start=$SECONDS
  timeout "$TIMEOUT" "$BIN" scan "$url" >"$OUT/$name.txt" 2>&1
  code=$?
  secs=$((SECONDS - start))

  if [ "$code" -eq 124 ]; then
    result=timeout
  elif grep -q '^Scan: INCONCLUSIVE' "$OUT/$name.txt"; then
    result=INCONCLUSIVE
  elif grep -q '^No findings' "$OUT/$name.txt"; then
    result=clean
  elif [ "$code" -eq 2 ]; then
    result=error
  else
    result=findings
  fi

  summary="$(grep '^Summary:' "$OUT/$name.txt" | tail -1)"
  count() { echo "$summary" | sed -n "s/.* \([0-9]*\) $1.*/\1/p"; }
  skipped="$(sed -n 's/^Not fully analyzed ([0-9]*): //p' "$OUT/$name.txt" | head -1)"
  scan_time="$(sed -n 's/^Scan time: //p' "$OUT/$name.txt" | tail -1)"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$repo" "$head" "$result" "$code" \
    "$(count critical)" "$(count high)" "$(count medium)" "$(count low)" "$(count info)" \
    "${skipped:--}" "$secs" "${scan_time:--}" >>"$OUT/results.tsv"
done

# The summary as a table of fixed widths (no `column`, which is not everywhere).
while IFS="$(printf '\t')" read -r repo head result code critical high medium low info skipped secs scan; do
  printf '%-22s %-13s %-13s %-5s %-9s %-5s %-7s %-4s %-5s %-52s %-6s %s\n' \
    "$repo" "$head" "$result" "$code" "$critical" "$high" "$medium" "$low" "$info" "$skipped" "$secs" "$scan"
done <"$OUT/results.tsv"
