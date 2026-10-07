resource "google_compute_firewall" "fw" {
  name          = "fw"
  network       = "default"
  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["web"]

  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }
}
