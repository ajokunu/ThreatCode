resource "google_sql_database_instance" "main" {
  name             = "main"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-7680"

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
    }
  }
}
