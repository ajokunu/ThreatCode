resource "google_bigquery_dataset" "analytics" {
  dataset_id = "analytics"
  location   = "US"

  access {
    role          = "READER"
    special_group = "allAuthenticatedUsers"
  }
}
