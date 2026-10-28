resource "aws_kms_key" "lab" {
  description             = "Lab customer managed key."
  deletion_window_in_days = 30
  # PLANTED: automatic annual rotation is off.
  enable_key_rotation = false
  policy              = data.aws_iam_policy_document.kms.json

  tags = local.common_tags
}

resource "aws_kms_alias" "lab" {
  name          = "alias/cloud-misconfig-lab"
  target_key_id = aws_kms_key.lab.key_id
}

data "aws_iam_policy_document" "kms" {
  statement {
    sid    = "RootAdmin"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }
}

# PLANTED: one region only, and log-file validation is off, so a deleted
# or edited log object would not fail the digest check.
resource "aws_cloudtrail" "lab" {
  name                          = "lab-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = false
  enable_log_file_validation    = false
  include_global_service_events = false
  enable_logging                = true

  tags = local.common_tags
}
