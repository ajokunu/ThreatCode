resource "google_sql_database_instance" "main" {
  name             = "main"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-7680"

    ip_configuration {
      ipv4_enabled    = false
      private_network = "projects/shop-prod/global/networks/shop-vpc"
      ssl_mode        = "ALLOW_UNENCRYPTED_AND_ENCRYPTED"
    }
  }
}
