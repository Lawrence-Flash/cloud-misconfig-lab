# IAM policy with Action * and Resource *

## What it is

The instance role's inline policy allows `Action "*"` on `Resource "*"`. The role can be assumed only by `ec2.amazonaws.com`, and it is attached to the lab instance. The trust policy is narrow. The permissions policy is not.

## Real-world risk

Anything running as that instance, including a stolen IMDSv1 credential, can call any IAM action the account allows a role to call: read every bucket, change security groups, create keys, create users. One compromised process becomes an administrator. The fix is a policy that names the bucket and the two read actions the instance actually needs.

## Scanner checks

Checkov reported these on `aws_iam_policy_document.app_admin`:

| Check | Name in the JSON |
| --- | --- |
| `CKV_AWS_1` | full `*:*` administrative privileges |
| `CKV2_AWS_40` | full IAM privileges |
| `CKV_AWS_49` | `*` as the action |
| `CKV_AWS_107` | credentials exposure |
| `CKV_AWS_108` | data exfiltration |
| `CKV_AWS_109` | permissions management without constraints |
| `CKV_AWS_110` | privilege escalation |
| `CKV_AWS_111` | write access without constraints |
| `CKV_AWS_356` | `*` as the resource |

The Trivy config scan did not report an IAM wildcard check. I am not adding one it did not print.

`CKV_AWS_1`, `CKV2_AWS_40`, `CKV_AWS_49`, `CKV_AWS_107`, `CKV_AWS_108`, and `CKV_AWS_110` are 0 in `fixed/`. `CKV_AWS_109`, `CKV_AWS_111`, and `CKV_AWS_356` drop from 2 to 1. The remaining hit is `aws_iam_policy_document.kms`, the key policy, which still has `resources = ["*"]`. A KMS key policy has to use `*` as the resource. That residual is listed in `docs/scan-summary.md`. It is not the instance role.

## Fix

```diff
--- vulnerable/iam.tf
+++ fixed/iam.tf
@@
-data "aws_iam_policy_document" "app_admin" {
-  statement {
-    sid       = "Admin"
-    effect    = "Allow"
-    actions   = ["*"]
-    resources = ["*"]
-  }
-}
+data "aws_iam_policy_document" "app_read" {
+  statement {
+    sid       = "ListLabData"
+    effect    = "Allow"
+    actions   = ["s3:ListBucket"]
+    resources = [aws_s3_bucket.data.arn]
+  }
+
+  statement {
+    sid       = "ReadLabObjects"
+    effect    = "Allow"
+    actions   = ["s3:GetObject"]
+    resources = ["${aws_s3_bucket.data.arn}/*"]
+  }
+}
```

Excerpt of `diff -u vulnerable/iam.tf fixed/iam.tf`.
