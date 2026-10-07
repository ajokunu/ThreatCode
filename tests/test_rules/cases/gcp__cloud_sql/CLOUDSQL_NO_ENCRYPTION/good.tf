resource "google_sql_database_instance" "main" {
  name                = "main"
  database_version    = "POSTGRES_15"
  region              = "us-central1"
  encryption_key_name = "projects/shop-prod/locations/us-central1/keyRings/db/cryptoKeys/main"

  settings {
    tier = "db-custom-2-7680"
  }
}
