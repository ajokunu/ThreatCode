resource "google_storage_bucket" "assets" {
  name                        = "shop-prod-assets"
  location                    = "US"
  uniform_bucket_level_access = true


  logging {
    log_bucket        = "shop-prod-logs"
    log_object_prefix = "assets"
  }
}
