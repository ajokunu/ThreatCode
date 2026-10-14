resource "google_cloud_run_service" "svc" {
  name     = "svc"
  location = "us-central1"

  template {
    spec {
      containers {
        image = "gcr.io/shop-prod/app:1.4.2"
      }
    }
  }
}

resource "google_cloud_run_service_iam_member" "invoker" {
  service  = google_cloud_run_service.svc.name
  location = google_cloud_run_service.svc.location
  role     = "roles/run.invoker"
  member   = "group:web-callers@example.com"
}
