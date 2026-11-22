#!/usr/bin/env bash
# Builds reproducible local release artifacts and SHA-256 checksums for the
# AWS Clarity local scanner. Does NOT publish or upload anything.
set -euo pipefail

VERSION="1.0.0"
OUT_DIR="dist-release"
ARCHIVE_NAME="aws-clarity-local-${VERSION}.tar.gz"

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}/staging/aws-clarity-${VERSION}"

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

(
  cd "${OUT_DIR}"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${ARCHIVE_NAME}" > SHA256SUMS.txt
  else
    sha256sum "${ARCHIVE_NAME}" > SHA256SUMS.txt
  fi
)

echo "Built local release artifact (not published):"
cat "${OUT_DIR}/SHA256SUMS.txt"
