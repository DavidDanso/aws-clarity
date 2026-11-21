#!/bin/bash
set -e
echo "🔨 Rebuilding Lambda package..."
rm -rf backend/lambda_package infra/lambda.zip
mkdir -p backend/lambda_package
python3 -m pip install -r backend/requirements.txt -t backend/lambda_package/ --quiet
cp backend/lambda_handler.py backend/lambda_package/
cp backend/utils.py backend/lambda_package/
cp backend/exceptions.py backend/lambda_package/
cp -r backend/scanner/ backend/lambda_package/scanner/
(cd backend/lambda_package && zip -r ../../infra/lambda.zip . -x "*.pyc" -x "*/__pycache__/*" >/dev/null)
echo "✅ Lambda package built cleanly"

echo "🚀 Running terraform apply..."
terraform -chdir=infra apply -auto-approve

echo "🔄 Syncing frontend/.env from Terraform outputs..."
API_URL=$(terraform -chdir=infra output -raw api_gateway_url)
APP_ACCOUNT_ID=$(terraform -chdir=infra output -raw app_account_id)
cat > frontend/.env <<EOF
VITE_API_URL=${API_URL}
VITE_APP_ACCOUNT_ID=${APP_ACCOUNT_ID}
EOF
echo "✅ Synced frontend/.env -> ${API_URL}"
