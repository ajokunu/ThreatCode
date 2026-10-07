resource "google_compute_firewall" "fw" {
  name          = "fw"
  network       = "default"
  direction     = "INGRESS"
  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["web"]

  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }
}
