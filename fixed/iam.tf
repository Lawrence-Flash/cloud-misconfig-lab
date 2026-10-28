resource "aws_iam_role" "app" {
  name = "lab-app"

  assume_role_policy = data.aws_iam_policy_document.app_trust.json

  tags = local.common_tags
}

data "aws_iam_policy_document" "app_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# FIXED: the instance role can only list the lab bucket and read its objects.
resource "aws_iam_role_policy" "app" {
  name = "lab-app-read-data"
  role = aws_iam_role.app.id

  policy = data.aws_iam_policy_document.app_read.json
}

data "aws_iam_policy_document" "app_read" {
  statement {
    sid       = "ListLabData"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.data.arn]
  }

  statement {
    sid       = "ReadLabObjects"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.data.arn}/*"]
  }
}

resource "aws_iam_instance_profile" "app" {
  name = "lab-app"
  role = aws_iam_role.app.name
}

resource "aws_iam_role" "rds_monitoring" {
  name               = "lab-rds-monitoring"
  assume_role_policy = data.aws_iam_policy_document.rds_monitoring_trust.json

  tags = local.common_tags
}

data "aws_iam_policy_document" "rds_monitoring_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["monitoring.rds.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

resource "aws_iam_role" "trail_logs" {
  name               = "lab-cloudtrail-logs"
  assume_role_policy = data.aws_iam_policy_document.trail_logs_trust.json

  tags = local.common_tags
}

data "aws_iam_policy_document" "trail_logs_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "trail_logs" {
  name = "lab-cloudtrail-logs"
  role = aws_iam_role.trail_logs.id

  policy = data.aws_iam_policy_document.trail_logs.json
}

data "aws_iam_policy_document" "trail_logs" {
  statement {
    sid    = "WriteTrailLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.trail.arn}:*"]
  }
}
