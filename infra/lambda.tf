resource "aws_cloudwatch_log_group" "scanner" {
  name              = "/aws/lambda/${var.app_name}-scanner"
  retention_in_days = var.log_retention_days
}

resource "aws_lambda_function" "scanner" {
  function_name                  = "${var.app_name}-backend"
  role                           = aws_iam_role.lambda_exec.arn
  handler                        = "lambda_handler.handler"
  runtime                        = "python3.12"
  memory_size                    = var.lambda_memory
  timeout                        = var.lambda_timeout
  reserved_concurrent_executions = var.lambda_reserved_concurrency

  filename         = "lambda.zip"
  source_code_hash = filebase64sha256("lambda.zip")

  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.scanner.name
  }

  environment {
    variables = {
      ENVIRONMENT           = "prod"
      SCAN_TABLE_NAME       = aws_dynamodb_table.scans.name
      SCANS_ENABLED         = var.scans_enabled ? "true" : "false"
      SCAN_COOLDOWN_SECONDS = tostring(var.scan_cooldown_seconds)
      MAX_CONCURRENT_SCANS  = tostring(var.max_concurrent_scans)
    }
  }

  depends_on = [aws_cloudwatch_log_group.scanner]
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scanner.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.api.execution_arn}/*/*"
}
