output "api_gateway_url" {
  value = "${aws_api_gateway_stage.prod.invoke_url}/scan"
}

output "cloudfront_url" {
  value = "https://${aws_cloudfront_distribution.frontend.domain_name}"
}

output "lambda_function_name" {
  value = aws_lambda_function.scanner.function_name
}

output "s3_bucket_name" {
  value = aws_s3_bucket.frontend.id
}

output "app_account_id" {
  value = data.aws_caller_identity.current.account_id
}
