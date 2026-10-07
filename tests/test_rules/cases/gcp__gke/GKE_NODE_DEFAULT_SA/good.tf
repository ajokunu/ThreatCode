resource "google_container_node_pool" "main" {
  name       = "main"
  cluster    = "main"
  location   = "us-central1"
  node_count = 3


  node_config {
    service_account = "gke-nodes@shop-prod.iam.gserviceaccount.com"
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]
  }
}
