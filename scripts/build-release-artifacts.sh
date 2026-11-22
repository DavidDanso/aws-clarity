#!/usr/bin/env bash
# Builds reproducible local Python release artifacts (wheel, sdist, versioned
# source tarball) and SHA256SUMS.txt for the AWS Clarity local scanner.
# Does NOT publish or upload anything automatically.
set -euo pipefail

VERSION="1.0.0"
OUT_DIR="dist-release"
ARCHIVE_NAME="aws-clarity-local-${VERSION}.tar.gz"

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}/staging/aws-clarity-${VERSION}"

# 1. Versioned standalone source archive
cp pyproject.toml README.md SECURITY.md "${OUT_DIR}/staging/aws-clarity-${VERSION}/"
mkdir -p "${OUT_DIR}/staging/aws-clarity-${VERSION}/backend/scanner"
cp backend/aws_clarity_cli.py \
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
PYTHON_BIN="${PYTHON_BIN:-python3}"
if "${PYTHON_BIN}" -c "import build" >/dev/null 2>&1; then
  "${PYTHON_BIN}" -m build --outdir "${OUT_DIR}" .
fi

# 3. SHA-256 checksums across all generated distribution files
(
  cd "${OUT_DIR}"
  FILES=(*.tar.gz)
  if compgen -G "*.whl" >/dev/null; then
    FILES+=(*.whl)
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${FILES[@]}" > SHA256SUMS.txt
  else
    sha256sum "${FILES[@]}" > SHA256SUMS.txt
  fi
)

echo "Built local release artifacts (not published):"
cat "${OUT_DIR}/SHA256SUMS.txt"
