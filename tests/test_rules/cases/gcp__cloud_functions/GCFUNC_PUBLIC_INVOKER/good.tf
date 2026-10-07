resource "google_cloudfunctions_function" "fn" {
  name                  = "fn"
  runtime               = "python312"
  region                = "us-central1"
  available_memory_mb   = 256
  source_archive_bucket = "shop-prod-functions"
  source_archive_object = "fn.zip"
  entry_point           = "handler"
  trigger_http          = true
}

resource "google_cloudfunctions_function_iam_member" "invoker" {
  cloud_function = google_cloudfunctions_function.fn.name
  region         = google_cloudfunctions_function.fn.region
  role           = "roles/cloudfunctions.invoker"
  member         = "serviceAccount:gateway@shop-prod.iam.gserviceaccount.com"
}
