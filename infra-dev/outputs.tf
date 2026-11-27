output "cloudfront_url" {
  value = "https://${aws_cloudfront_distribution.frontend.domain_name}"
}

output "cloudfront_distribution_id" {
  value = aws_cloudfront_distribution.frontend.id
}

output "s3_bucket_name" {
  value = aws_s3_bucket.frontend.id
}

output "oac_id" {
  value = aws_cloudfront_origin_access_control.frontend.id
}

output "response_headers_policy_id" {
  value = aws_cloudfront_response_headers_policy.security_headers.id
}
