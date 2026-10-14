resource "google_sql_database_instance" "main" {
  name             = "main"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-7680"

    ip_configuration {
      ipv4_enabled = true
      ssl_mode     = "ENCRYPTED_ONLY"

      authorized_networks {
        name  = "everyone"
        value = "0.0.0.0/0"
      }
    }
  }
}
