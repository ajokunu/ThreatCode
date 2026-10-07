resource "aws_apigatewayv2_route" "items" {
  api_id             = aws_apigatewayv2_api.http.id
  route_key          = "GET /items"
  authorization_type = "NONE"
}
