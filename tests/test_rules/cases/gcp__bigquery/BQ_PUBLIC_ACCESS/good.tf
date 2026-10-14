resource "google_bigquery_dataset" "analytics" {
  dataset_id = "analytics"
  location   = "US"

  access {
    role           = "READER"
    group_by_email = "analysts@example.com"
  }
}
