resource "google_bigquery_dataset" "analytics" {
  dataset_id = "analytics"
  location   = "US"

  access {
    role           = "READER"
    group_by_email = "analysts@example.com"
  }

  default_encryption_configuration {
    kms_key_name = "projects/shop-prod/locations/us/keyRings/bq/cryptoKeys/analytics"
  }
}
