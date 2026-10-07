resource "aws_cloudfront_distribution" "cdn" {
  enabled = true
  web_acl_id = "arn:aws:wafv2:us-east-1:111122223333:global/webacl/cdn/0a1b2c3d-0000-1111-2222-333344445555"

  origin {
    domain_name = "app.example.com"
    origin_id   = "app"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id       = "app"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  logging_config {
    bucket = "cdn-logs.s3.amazonaws.com"
    prefix = "cdn"
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}
