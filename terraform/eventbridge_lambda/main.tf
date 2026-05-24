terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.0" }
  }
}

variable "lambda_function_name" { default = "aws-cloud-security-scanner" }
variable "scanner_s3_bucket" { description = "Bucket containing packaged Lambda zip" }
variable "scanner_s3_key" { description = "S3 key for packaged Lambda zip" }

resource "aws_iam_role" "scanner_lambda" {
  name = "aws-cloud-security-scanner-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "basic" {
  role       = aws_iam_role.scanner_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function" "scanner" {
  function_name = var.lambda_function_name
  role          = aws_iam_role.scanner_lambda.arn
  handler       = "handler.handler"
  runtime       = "python3.11"
  s3_bucket     = var.scanner_s3_bucket
  s3_key        = var.scanner_s3_key
  timeout       = 60
}

resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = "aws-cloud-security-scanner-guardduty"
  description = "Send GuardDuty findings to scanner Lambda"
  event_pattern = jsonencode({
    source = ["aws.guardduty"],
    "detail-type" = ["GuardDuty Finding"]
  })
}

resource "aws_cloudwatch_event_target" "scanner" {
  rule = aws_cloudwatch_event_rule.guardduty.name
  arn  = aws_lambda_function.scanner.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty.arn
}
