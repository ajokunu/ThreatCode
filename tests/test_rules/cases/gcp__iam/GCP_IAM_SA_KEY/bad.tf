resource "google_service_account" "ci" {
  account_id   = "ci"
  display_name = "CI"
}

resource "google_service_account_key" "ci" {
  service_account_id = google_service_account.ci.name
}
