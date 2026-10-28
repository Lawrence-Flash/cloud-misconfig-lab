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

# PLANTED: this role can call any action on any resource.
resource "aws_iam_role_policy" "app" {
  name = "lab-app-admin"
  role = aws_iam_role.app.id

  policy = data.aws_iam_policy_document.app_admin.json
}

data "aws_iam_policy_document" "app_admin" {
  statement {
    sid       = "Admin"
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
}

resource "aws_iam_instance_profile" "app" {
  name = "lab-app"
  role = aws_iam_role.app.name
}
