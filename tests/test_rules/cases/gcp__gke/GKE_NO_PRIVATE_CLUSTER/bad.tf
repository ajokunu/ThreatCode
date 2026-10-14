resource "google_container_cluster" "main" {
  name                     = "main"
  location                 = "us-central1"
  remove_default_node_pool = true
  initial_node_count       = 1


  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = "203.0.113.0/24"
      display_name = "office"
    }
  }

  workload_identity_config {
    workload_pool = "shop-prod.svc.id.goog"
  }

  datapath_provider = "ADVANCED_DATAPATH"
}
