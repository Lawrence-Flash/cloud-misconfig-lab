# S3 access logging and versioning

## What it is

The data bucket does not enable versioning, does not write server access logs, and has no lifecycle rule. The log bucket and the trail bucket already do all three in both copies. The planted gap is the data bucket.

## Real-world risk

Without versioning, an overwrite or a delete is the object gone. Access logs are the record of who called `GetObject` and `PutObject`. CloudTrail can cover API calls too, but server access logs are the bucket's own record of object requests, including ones CloudTrail data events might not be configured to capture. A lifecycle rule that aborts incomplete multipart uploads is a smaller hygiene item the scanner also reported on this bucket.

## Scanner checks

On `aws_s3_bucket.data`:

| Scanner | Check | Severity in the JSON |
| --- | --- | --- |
| Checkov | `CKV_AWS_21` | unscored, versioning |
| Checkov | `CKV_AWS_18` | unscored, access logging |
| Checkov | `CKV2_AWS_61` | unscored, lifecycle configuration |
| Trivy | `AWS-0090` | medium, versioning |
| Trivy | `AWS-0089` | low, access logging |

All five are 0 in `fixed/`.

## Fix

```diff
--- vulnerable/storage.tf
+++ fixed/storage.tf
@@
+resource "aws_s3_bucket_versioning" "data" {
+  bucket = aws_s3_bucket.data.id
+
+  versioning_configuration {
+    status = "Enabled"
+  }
+}
+
+resource "aws_s3_bucket_logging" "data" {
+  bucket = aws_s3_bucket.data.id
+
+  target_bucket = aws_s3_bucket.logs.id
+  target_prefix = "s3-access/data/"
+}
+
+resource "aws_s3_bucket_lifecycle_configuration" "data" {
+  bucket = aws_s3_bucket.data.id
+
+  rule {
+    id     = "abort-incomplete-multipart"
+    status = "Enabled"
+    abort_incomplete_multipart_upload {
+      days_after_initiation = 7
+    }
+  }
+}
```

Excerpt of `diff -u vulnerable/storage.tf fixed/storage.tf`.
