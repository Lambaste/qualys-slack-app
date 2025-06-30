provider "aws" {
  region = "us-west-2"
}

# IAM Role for Lambda
resource "aws_iam_role" "lambda_exec" {
  name = "slack-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "lambda.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "basic_execution" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Allow Lambda to access Secrets Manager
resource "aws_iam_policy" "secrets_access" {
  name = "lambda-secrets-access"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "secretsmanager:GetSecretValue"
        ],
        Resource = [
          var.qualy_secret_arn,
          var.slack_secret_arn
        ]
      }
    ]
  })
}

resource "aws_iam_policy_attachment" "attach_secrets" {
  name       = "attach-lambda-secrets"
  roles      = [aws_iam_role.lambda_exec.name]
  policy_arn = aws_iam_policy.secrets_access.arn
}

# Lambda Function
resource "aws_lambda_function" "slack_app" {
  function_name = "slack-app"

  filename         = "../lambda/app.zip"
  source_code_hash = filebase64sha256("../lambda/app.zip")
  handler          = "app.lambda_handler"
  runtime          = "python3.11"
  timeout          = 30
  memory_size      = 256

  role = aws_iam_role.lambda_exec.arn

  environment {
    variables = {
      CUSTOMER_SLACK_SECRET = var.slack_secret_name
      QUALYS_SECRET_NAME    = var.qualy_secret_name
    }
  }
}

# API Gateway (HTTP)
resource "aws_apigatewayv2_api" "slack_api" {
  name          = "slack-api"
  protocol_type = "HTTP"
}

resource "aws_lambda_permission" "apigw_permission" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.slack_app.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.slack_api.execution_arn}/*/*"
}

resource "aws_apigatewayv2_integration" "lambda_integration" {
  api_id                 = aws_apigatewayv2_api.slack_api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.slack_app.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "slack_route" {
  api_id    = aws_apigatewayv2_api.slack_api.id
  route_key = "POST /slack/events"
  target    = "integrations/${aws_apigatewayv2_integration.lambda_integration.id}"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.slack_api.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.apigw_logs.arn
    format = jsonencode({
      requestId     = "$context.requestId",
      sourceIp      = "$context.identity.sourceIp",
      requestTime   = "$context.requestTime",
      httpMethod    = "$context.httpMethod",
      routeKey      = "$context.routeKey",
      status        = "$context.status"
    })
  }
}

resource "aws_cloudwatch_log_group" "apigw_logs" {
  name              = "/aws/api-gateway/slack-app"
  retention_in_days = 14
}


