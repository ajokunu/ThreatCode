resource "aws_api_gateway_stage" "prod" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  deployment_id = aws_api_gateway_deployment.api.id
  stage_name    = "prod"

  access_log_settings {
    destination_arn = "arn:aws:logs:us-east-1:111122223333:log-group:/apigw/api"
    format          = jsonencode({ requestId = "$context.requestId" })
  }
}
