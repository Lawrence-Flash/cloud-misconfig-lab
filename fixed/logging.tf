resource "aws_kms_key" "lab" {
  description             = "Lab customer managed key."
  deletion_window_in_days = 30
  # FIXED: AWS rotates the key material automatically once a year.
  enable_key_rotation = true
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

  statement {
    sid    = "CloudTrailEncrypt"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = [
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${var.account_id}:trail/lab-trail"]
    }
  }

  statement {
    sid    = "CloudWatchLogs"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*",
    ]
    resources = ["*"]

    condition {
      test     = "ArnEquals"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${var.aws_region}:${var.account_id}:log-group:lab-cloudtrail"]
    }
  }

  statement {
    sid    = "PersistentDataServices"
    effect = "Allow"

    principals {
      type = "Service"
      identifiers = [
        "rds.amazonaws.com",
        "ec2.amazonaws.com",
        "s3.amazonaws.com",
      ]
    }

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
      "kms:CreateGrant",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [var.account_id]
    }
  }
}

resource "aws_cloudwatch_log_group" "trail" {
  name              = "lab-cloudtrail"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.lab.arn

  tags = local.common_tags
}

resource "aws_cloudtrail" "lab" {
  name                          = "lab-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  include_global_service_events = true
  enable_logging                = true
  kms_key_id                    = aws_kms_key.lab.arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.trail_logs.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.data.arn}/"]
    }
  }

  tags = local.common_tags
}
