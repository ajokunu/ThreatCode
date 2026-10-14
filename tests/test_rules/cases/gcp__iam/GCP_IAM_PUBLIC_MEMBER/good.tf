resource "google_kms_crypto_key_iam_member" "grant" {
  crypto_key_id = "projects/shop-prod/locations/global/keyRings/app/cryptoKeys/main"
  role    = "roles/cloudkms.cryptoKeyDecrypter"
  member  = "serviceAccount:app@shop-prod.iam.gserviceaccount.com"
}
