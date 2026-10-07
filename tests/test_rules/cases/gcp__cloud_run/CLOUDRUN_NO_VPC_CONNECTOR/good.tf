resource "google_cloud_run_service" "svc" {
  name     = "svc"
  location = "us-central1"

  template {
    metadata {
      annotations = {
        "run.googleapis.com/vpc-access-connector" = "projects/shop-prod/locations/us-central1/connectors/app"
        "autoscaling.knative.dev/maxScale"        = "10"
      }
    }

    spec {
      containers {
        image = "gcr.io/shop-prod/app:1.4.2"
      }
    }
  }
}
