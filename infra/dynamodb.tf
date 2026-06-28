resource "aws_dynamodb_table" "scans" {
  name         = "aws-clarity-scans"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "scan_id"

  attribute {
    name = "scan_id"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
}

output "scans_table_name" {
  value = aws_dynamodb_table.scans.name
}
