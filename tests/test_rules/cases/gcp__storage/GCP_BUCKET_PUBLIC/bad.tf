resource "google_storage_bucket_iam_member" "public" {
  bucket = "shop-prod-assets"
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
