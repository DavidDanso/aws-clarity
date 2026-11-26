#!/usr/bin/env bash
# Builds reproducible local Python release artifacts (wheel, sdist, versioned
# source tarball) and SHA256SUMS.txt for the AWS Clarity local scanner.
# Does NOT publish or upload anything automatically.
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python3}"
VERSION="$("${PYTHON_BIN}" -c '
import re
try:
    import tomllib
    print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])
except ModuleNotFoundError:
    txt = open("pyproject.toml", encoding="utf-8").read()
    m = re.search(r"(?ms)^\[project\].*?^\s*version\s*=\s*\"([^\"]+)\"", txt)
    if not m:
        raise SystemExit("Unable to read [project].version from pyproject.toml")
    print(m.group(1))
')"
OUT_DIR="${OUT_DIR:-dist-release}"
ARCHIVE_NAME="aws-clarity-local-${VERSION}.tar.gz"

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}/staging/aws-clarity-${VERSION}"

# 1. Versioned standalone source archive (includes api_guard.py and LICENSE)
cp pyproject.toml README.md SECURITY.md LICENSE CHANGELOG.md "${OUT_DIR}/staging/aws-clarity-${VERSION}/"
mkdir -p "${OUT_DIR}/staging/aws-clarity-${VERSION}/backend/scanner"
cp backend/api_guard.py \
   backend/aws_clarity_cli.py \
   backend/local_engine.py \
   backend/lambda_handler.py \
   backend/utils.py \
   backend/exceptions.py \
   backend/requirements.txt \
   "${OUT_DIR}/staging/aws-clarity-${VERSION}/backend/"
cp backend/scanner/*.py "${OUT_DIR}/staging/aws-clarity-${VERSION}/backend/scanner/"

tar -czf "${OUT_DIR}/${ARCHIVE_NAME}" -C "${OUT_DIR}/staging" "aws-clarity-${VERSION}"
rm -rf "${OUT_DIR}/staging"

# 2. PEP 517 Python wheel (.whl) and source distribution (.tar.gz) when `build` is available
if "${PYTHON_BIN}" -c "import build" >/dev/null 2>&1; then
  "${PYTHON_BIN}" -m build --outdir "${OUT_DIR}" .
else
  echo "WARNING: Python 'build' package not installed; skipped .whl and sdist generation." >&2
fi

# 3. SHA-256 checksums across all generated distribution files (never includes SHA256SUMS.txt itself)
(
  cd "${OUT_DIR}"
  FILES=()
  for f in *.tar.gz *.whl; do
    if [ -f "$f" ]; then
      FILES+=("$f")
    fi
  done
  if [ "${#FILES[@]}" -eq 0 ]; then
    echo "ERROR: No release artifacts found in ${OUT_DIR}" >&2
    exit 1
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${FILES[@]}" > SHA256SUMS.txt
    shasum -a 256 -c SHA256SUMS.txt
  else
    sha256sum "${FILES[@]}" > SHA256SUMS.txt
    sha256sum -c SHA256SUMS.txt
  fi
)

echo "Built local release artifacts (v${VERSION}, not published):"
cat "${OUT_DIR}/SHA256SUMS.txt"
