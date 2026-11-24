#!/bin/bash
set -euo pipefail

echo "🚀 Applying static frontend Terraform configuration (S3 + CloudFront only)..."
terraform -chdir=infra apply -auto-approve

S3_BUCKET=$(terraform -chdir=infra output -raw s3_bucket_name)
CF_URL=$(terraform -chdir=infra output -raw cloudfront_url)
CF_DIST_ID=$(terraform -chdir=infra output -raw cloudfront_distribution_id)

echo "🏗️ Building & verifying local-first static frontend..."
npm --prefix frontend run build
npm --prefix frontend run verify

echo "☁️ Syncing frontend/dist/ to s3://${S3_BUCKET}..."
aws s3 sync frontend/dist/ "s3://${S3_BUCKET}" --delete

echo "🔄 Invalidating CloudFront cache (${CF_DIST_ID})..."
aws cloudfront create-invalidation --distribution-id "${CF_DIST_ID}" --paths "/*" >/dev/null

echo "✅ Static frontend deployed cleanly -> ${CF_URL}"
