#!/usr/bin/env bash
# Reproduce the committed scan-results/ from the Terraform in this repo.
# Nothing is deployed. terraform apply is not invoked.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export PATH="${HOME}/.local/bin:${PATH}"

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "scan.sh: missing '$1'. See the README quick start." >&2
    exit 1
  fi
}

need terraform
need checkov
need trivy
need gitleaks
need python3

mkdir -p scan-results

{
  echo "terraform $(terraform version -json | python3 -c 'import json,sys; print(json.load(sys.stdin)["terraform_version"])')"
  echo "checkov $(checkov --version | head -n 1)"
  echo "trivy $(trivy --version | awk 'NR==1 {print $2}')"
  echo "gitleaks $(gitleaks version)"
} > scan-results/tool-versions.txt

terraform fmt -recursive

for dir in vulnerable fixed; do
  terraform -chdir="$dir" init -backend=false -input=false
  terraform -chdir="$dir" validate
done

checkov -d vulnerable \
  --framework terraform --framework secrets \
  --download-external-modules false \
  --quiet --soft-fail \
  -o json > scan-results/checkov-vulnerable.json

checkov -d fixed \
  --framework terraform --framework secrets \
  --download-external-modules false \
  --quiet --soft-fail \
  -o json > scan-results/checkov-fixed.json

trivy config --skip-version-check --format json --output scan-results/trivy-vulnerable.json vulnerable/
trivy config --skip-version-check --format json --output scan-results/trivy-fixed.json fixed/

python3 scripts/normalize_scans.py
python3 scripts/gitleaks_demo.py

if ! gitleaks detect --no-git --source . --redact --report-format json --report-path scan-results/gitleaks.json --exit-code 1; then
  echo "scan.sh: gitleaks found a leak. The planted value must stay allowlisted only on its vulnerable/variables.tf line." >&2
  exit 1
fi

# gitleaks writes no file when there is nothing to report.
if [[ ! -s scan-results/gitleaks.json ]]; then
  printf '[]\n' > scan-results/gitleaks.json
fi

python3 -m misconfig report
python3 -m misconfig gate --side vulnerable --expect-findings
python3 -m misconfig gate --side fixed --fail-on CRITICAL,HIGH

echo "scan.sh: results are in scan-results/ and docs/scan-summary.md"
