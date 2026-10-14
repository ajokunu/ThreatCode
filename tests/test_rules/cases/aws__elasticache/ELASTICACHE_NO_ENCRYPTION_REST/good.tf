resource "aws_elasticache_replication_group" "sessions" {
  replication_group_id = "sessions"
  description          = "session cache"
  node_type            = "cache.t3.small"
  num_cache_clusters   = 2
  at_rest_encryption_enabled = true
}
