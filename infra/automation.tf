resource "null_resource" "frontend_deploy" {
  depends_on = [
    aws_api_gateway_stage.prod,
    aws_s3_bucket.frontend,
    aws_cloudfront_distribution.frontend
  ]

  triggers = {
    api_url         = aws_api_gateway_stage.prod.invoke_url
    account_id      = data.aws_caller_identity.current.account_id
    distribution_id = aws_cloudfront_distribution.frontend.id
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    working_dir = "${path.module}/../frontend"
    command     = <<EOT
printf 'VITE_API_URL=%s\nVITE_APP_ACCOUNT_ID=%s\n' '${aws_api_gateway_stage.prod.invoke_url}' '${data.aws_caller_identity.current.account_id}' > .env && \
npm install && \
npm run build && \
aws s3 sync dist/ s3://${aws_s3_bucket.frontend.bucket}/ --delete && \
aws cloudfront create-invalidation --distribution-id ${aws_cloudfront_distribution.frontend.id} --paths '/*'
EOT
  }
}
