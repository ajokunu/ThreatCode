resource "google_cloudfunctions_function" "fn" {
  name                  = "fn"
  runtime               = "python312"
  region                = "us-central1"
  available_memory_mb   = 256
  source_archive_bucket = "shop-prod-functions"
  source_archive_object = "fn.zip"
  entry_point           = "handler"
  trigger_http          = true
  ingress_settings      = "ALLOW_INTERNAL_AND_GCLB"
}
