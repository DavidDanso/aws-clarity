#!/bin/bash
set -e
echo "🔨 Rebuilding Lambda package..."
rm -rf backend/lambda_package
mkdir backend/lambda_package
pip install -r backend/requirements.txt -t backend/lambda_package/ --quiet
cp backend/lambda_handler.py backend/lambda_package/
cp backend/utils.py backend/lambda_package/
cp backend/exceptions.py backend/lambda_package/
cp -r backend/scanner/ backend/lambda_package/scanner/
cd backend/lambda_package && zip -r ../../infra/lambda.zip . -x "*.pyc" -x "*/__pycache__/*" && cd ../..
echo "✅ Lambda package built"
echo "🚀 Running terraform apply..."
terraform -chdir=infra apply -auto-approve
echo "✅ Done"
