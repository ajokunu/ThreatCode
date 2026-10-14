resource "google_pubsub_topic" "events" {
  name         = "events"
  kms_key_name = "projects/shop-prod/locations/global/keyRings/pubsub/cryptoKeys/events"
}
