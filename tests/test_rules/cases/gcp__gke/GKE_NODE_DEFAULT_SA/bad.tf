resource "google_container_node_pool" "main" {
  name       = "main"
  cluster    = "main"
  location   = "us-central1"
  node_count = 3
}
