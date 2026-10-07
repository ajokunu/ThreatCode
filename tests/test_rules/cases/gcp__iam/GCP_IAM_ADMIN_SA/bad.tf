resource "google_project_iam_member" "grant" {
  project = "shop-prod"
  role    = "roles/owner"
  member  = "serviceAccount:ci@shop-prod.iam.gserviceaccount.com"
}
