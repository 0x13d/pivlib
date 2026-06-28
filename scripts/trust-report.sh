#!/usr/bin/env bash
# ────────────────────────────────────────────────────────────────────────────
# VENDORED FROM: /Users/ariugwu/Projects/_shared/trust-report/trust-report.sh
# SYNCED:        2026-05-22T22:10:13Z
# MASTER SHA256: c8f672c4405a507f40ce733f0f7228c43ab5e7d231555c274af693cf8aad9abe
# DO NOT EDIT IN PLACE — edit the master and run sync.sh.
# ────────────────────────────────────────────────────────────────────────────
# trust-report.sh — supply-chain trust report for this repo.
#
# Generates evidence that this project is well-formed and offline-friendly:
#   - SBOM (CycloneDX + SPDX) via syft
#   - npm/pnpm audit for every package.json found
#   - cargo audit + cargo deny if Cargo.toml is present
#   - License inventory (CSV) derived from the SBOM
#   - Static inventory of outbound-network call sites in source
#
# Re-runnable. Skips checks whose tools are not installed and prints
# install hints. Writes everything under reports/trust/. The committed
# summary is reports/trust/summary.md.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
OUT="$ROOT/reports/trust"
mkdir -p "$OUT"

# Gitignore inside reports/trust so only summary.md (and this ignore file)
# gets committed by default.
if [ ! -f "$OUT/.gitignore" ]; then
  cat >"$OUT/.gitignore" <<'EOF'
*
!.gitignore
!summary.md
EOF
fi

has() { command -v "$1" >/dev/null 2>&1; }

ROWS=()
row() { ROWS+=("| $1 | $2 | $3 |"); }

# ---------- SBOM (syft) ----------
if has syft; then
  if syft "dir:$ROOT" \
       -o "cyclonedx-json=$OUT/sbom.cyclonedx.json" \
       -o "spdx-json=$OUT/sbom.spdx.json" \
       -q >/dev/null 2>&1; then
    n=$(jq '.components | length' "$OUT/sbom.cyclonedx.json" 2>/dev/null || echo "?")
    row "OK" "SBOM (syft)" "$n components — sbom.cyclonedx.json, sbom.spdx.json"
  else
    row "FAIL" "SBOM (syft)" "syft run failed"
  fi
else
  row "SKIP" "SBOM" "install: brew install syft"
fi

# ---------- node audits ----------
NODE_DIRS=()
while IFS= read -r d; do NODE_DIRS+=("$d"); done < <(
  find . -maxdepth 4 -type f -name package.json \
    -not -path '*/node_modules/*' \
    -not -path '*/target/*' \
    -not -path '*/dist/*' \
    -not -path '*/.git/*' \
    -not -path '*/storybook-static/*' \
    -not -path '*/playwright-report/*' \
    -exec dirname {} \; | sort -u
)

vuln_total() {
  # Accept various npm/pnpm audit JSON shapes; print integer or "?"
  jq -r '
    if (.metadata.vulnerabilities.total // null) != null then
      .metadata.vulnerabilities.total
    elif (.metadata.vulnerabilities // null) != null then
      [.metadata.vulnerabilities | to_entries[] | select(.value|type=="number") | .value] | add
    else
      "?"
    end
  ' "$1" 2>/dev/null
}

for d in ${NODE_DIRS[@]+"${NODE_DIRS[@]}"}; do
  label="${d#./}"
  [ -z "$label" ] && label="root"
  [ "$label" = "." ] && label="root"
  tool="npm"
  if [ -f "$d/pnpm-lock.yaml" ] && has pnpm; then tool="pnpm"; fi
  safe="${label//\//_}"
  out_file="$OUT/audit-${tool}-${safe}.json"
  (cd "$d" && "$tool" audit --json 2>/dev/null) >"$out_file" || true
  if [ -s "$out_file" ]; then
    total=$(vuln_total "$out_file")
    [ -z "$total" ] && total="?"
    case "$total" in
      0)  row "OK"   "$tool audit ($label)" "0 vulnerabilities — $(basename "$out_file")" ;;
      \?) row "INFO" "$tool audit ($label)" "see $(basename "$out_file")" ;;
      *)  row "WARN" "$tool audit ($label)" "$total vulnerabilities — $(basename "$out_file")" ;;
    esac
  else
    rm -f "$out_file"
    row "SKIP" "$tool audit ($label)" "no audit output (no lockfile?)"
  fi
done

# ---------- cargo audit / deny ----------
if [ -f "$ROOT/Cargo.toml" ]; then
  if has cargo-audit; then
    if cargo audit --json >"$OUT/audit-cargo.json" 2>/dev/null; then
      :
    fi
    if [ -s "$OUT/audit-cargo.json" ]; then
      n=$(jq -r '.vulnerabilities.count // (.vulnerabilities.list | length) // 0' "$OUT/audit-cargo.json" 2>/dev/null || echo "?")
      case "$n" in
        0)  row "OK"   "cargo audit" "0 vulnerabilities — audit-cargo.json" ;;
        \?) row "INFO" "cargo audit" "see audit-cargo.json" ;;
        *)  row "WARN" "cargo audit" "$n vulnerabilities — audit-cargo.json" ;;
      esac
    else
      rm -f "$OUT/audit-cargo.json"
      row "SKIP" "cargo audit" "no output"
    fi
  else
    row "SKIP" "cargo audit" "install: cargo install cargo-audit"
  fi

  if has cargo-deny; then
    cargo deny --log-level error check advisories bans sources >"$OUT/cargo-deny.txt" 2>&1 || true
    if grep -qiE 'error|warning' "$OUT/cargo-deny.txt" 2>/dev/null; then
      row "INFO" "cargo deny" "findings — cargo-deny.txt"
    else
      row "OK" "cargo deny" "no findings — cargo-deny.txt"
    fi
  fi
fi

# ---------- License inventory (from CycloneDX SBOM) ----------
if [ -f "$OUT/sbom.cyclonedx.json" ]; then
  {
    echo "name,version,license"
    jq -r '.components[]? |
      [.name // "",
       .version // "",
       ((.licenses // []) | map(.license.id // .license.name // .expression // "?") | join(";"))]
      | @csv' "$OUT/sbom.cyclonedx.json" 2>/dev/null
  } >"$OUT/licenses.csv"
  rows=$(($(wc -l <"$OUT/licenses.csv" | tr -d ' ') - 1))
  uniq=$(tail -n +2 "$OUT/licenses.csv" | awk -F',' '{print $3}' | sort -u | wc -l | tr -d ' ')
  row "OK" "Licenses" "$rows components, $uniq distinct — licenses.csv"
fi

# ---------- Static network-call inventory ----------
NET_OUT="$OUT/network-calls.txt"
: >"$NET_OUT"
PATTERN='fetch\(|XMLHttpRequest|axios|http\.get|http\.post|https?://[a-zA-Z]|reqwest|isahc|ureq|hyper::|tonic'
for sub in src crates packages apps webapp frontend www tests lib; do
  [ -d "$ROOT/$sub" ] || continue
  grep -rEn \
    --include='*.ts' --include='*.tsx' --include='*.js' --include='*.mjs' --include='*.jsx' \
    --include='*.rs' --include='*.py' \
    --exclude-dir=node_modules --exclude-dir=target --exclude-dir=dist \
    --exclude-dir=build --exclude-dir=coverage --exclude-dir=storybook-static \
    --exclude-dir=playwright-report --exclude-dir=test-results --exclude-dir=__mocks__ \
    --exclude-dir=wasm --exclude-dir=wasm-node --exclude-dir=pkg --exclude-dir=.git \
    "$PATTERN" "$ROOT/$sub" 2>/dev/null \
    | grep -vE '://(localhost|127\.0\.0\.1|0\.0\.0\.0|schemas\.|www\.w3\.org|json-schema\.org|example\.com|example\.org)' \
    >>"$NET_OUT" || true
done

if [ -s "$NET_OUT" ]; then
  hits=$(wc -l <"$NET_OUT" | tr -d ' ')
  row "INFO" "Network-call inventory" "$hits source matches — network-calls.txt (review for outbound)"
else
  row "OK" "Network-call inventory" "no outbound patterns found in source"
fi

# ---------- Summary ----------
{
  echo "# Trust Report — $(basename "$ROOT")"
  echo
  echo "_Generated $(date -u +%Y-%m-%dT%H:%M:%SZ)_"
  echo
  echo "Static supply-chain checks. Re-run via \`bash scripts/trust-report.sh\`."
  echo "Artifacts in \`reports/trust/\`; only this \`summary.md\` is committed."
  echo
  echo "| Status | Check | Detail |"
  echo "|--------|-------|--------|"
  printf '%s\n' "${ROWS[@]}"
  echo
  echo "## Artifacts"
  echo
  ( cd "$OUT" && ls -1 | grep -vE '^(summary\.md|\.gitignore)$' | sed 's/^/- /' ) 2>/dev/null || true
  echo
  echo "## Reproduce"
  echo
  echo '```sh'
  echo 'bash scripts/trust-report.sh'
  echo '```'
  echo
  echo "Tools used (when present): syft, npm/pnpm audit, cargo-audit, cargo-deny, jq."
} >"$OUT/summary.md"

echo "Trust report written to $OUT/summary.md"
