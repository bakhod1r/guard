#!/usr/bin/env bash
# Fails unless every package in the coverage profile is at 100.0% statements.
# Usage: coverage-gate.sh <coverprofile> [threshold]
set -euo pipefail
profile="${1:?coverprofile required}"
threshold="${2:-100.0}"
[ -s "$profile" ] || { echo "coverage profile $profile missing or empty" >&2; exit 1; }

# Aggregate per package from the raw profile: file:start,end numStmts count
tail -n +2 "$profile" | awk -v t="$threshold" '
{
  split($1, a, ":"); file = a[1]
  pkg = file; sub(/\/[^\/]*$/, "", pkg)
  key = $1
  # atomic/count profiles may repeat blocks across test binaries: keep max count
  if (!(key in stmts)) { stmts[key] = $2; blockpkg[key] = pkg }
  if ($3 > 0) covered[key] = 1
}
END {
  for (k in stmts) { total[blockpkg[k]] += stmts[k]; if (k in covered) hit[blockpkg[k]] += stmts[k] }
  fail = 0
  n = asorti_portable(total, names)
  for (i = 1; i <= n; i++) {
    p = names[i]; pct = total[p] ? 100 * hit[p] / total[p] : 100
    status = (sprintf("%.1f", pct) + 0 < t + 0) ? "FAIL" : "ok"
    if (status == "FAIL") fail = 1
    printf "%-4s %6.1f%%  %s\n", status, pct, p
  }
  exit fail
}
function asorti_portable(src, dst,   k, n, i, j, tmp) {
  n = 0; for (k in src) dst[++n] = k
  for (i = 2; i <= n; i++) { tmp = dst[i]; for (j = i - 1; j > 0 && dst[j] > tmp; j--) dst[j+1] = dst[j]; dst[j+1] = tmp }
  return n
}' || status=$?
status=${status:-0}
echo "--- go tool cover -func total ---"
go tool cover -func="$profile" 2>/dev/null | tail -n 1 || true
exit $status
