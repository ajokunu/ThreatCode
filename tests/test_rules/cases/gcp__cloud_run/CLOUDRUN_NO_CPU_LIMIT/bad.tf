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
