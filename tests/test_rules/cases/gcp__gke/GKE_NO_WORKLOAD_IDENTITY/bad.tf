resource "google_container_cluster" "main" {
  name                     = "main"
  location                 = "us-central1"
  remove_default_node_pool = true
  initial_node_count       = 1


  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = "203.0.113.0/24"
      display_name = "office"
    }
  }

  datapath_provider = "ADVANCED_DATAPATH"
}
