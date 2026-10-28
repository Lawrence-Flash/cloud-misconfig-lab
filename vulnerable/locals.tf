locals {
  common_tags = {
    Project     = "cloud-misconfig-lab"
    Environment = "lab"
    ManagedBy   = "terraform"
  }

  data_bucket_name  = "${var.name_prefix}-${var.account_id}-data"
  logs_bucket_name  = "${var.name_prefix}-${var.account_id}-logs"
  trail_bucket_name = "${var.name_prefix}-${var.account_id}-trail"
}
