resource "google_service_account" "ci" {
  account_id   = "ci"
  display_name = "CI"
}

resource "google_service_account_key" "ci" {
  service_account_id = google_service_account.ci.name
  public_key_data    = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUMuLi4KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
}
