# Unencrypted S3

## What it is

The data bucket has no server-side encryption configuration. The log bucket and the CloudTrail bucket use SSE-S3 (`AES256`), not the lab's customer managed key.

## Real-world risk

Objects sit on disk in AWS's storage system without a key you control. SSE-S3 still encrypts, but the key is AWS-owned and you cannot rotate it or put a policy on it. A bucket with no encryption configuration is the weaker case: nothing in the template even asks for encryption, so a bucket policy or a later copy can land plaintext.

## Scanner checks

| Scanner | Check | Where |
| --- | --- | --- |
| Checkov | `CKV_AWS_145` | `aws_s3_bucket.data`, `aws_s3_bucket.logs`, `aws_s3_bucket.trail` |
| Trivy | `AWS-0132` | `aws_s3_bucket.data` and `aws_s3_bucket_server_side_encryption_configuration.trail` |

`CKV_AWS_145` is unscored. Trivy rated `AWS-0132` high. Trivy did not report the log bucket. Both checks are 0 in `fixed/`, where all three buckets use the customer managed key.

## Fix

```diff
--- vulnerable/storage.tf
+++ fixed/storage.tf
@@
+resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
+  bucket = aws_s3_bucket.data.id
+
+  rule {
+    apply_server_side_encryption_by_default {
+      sse_algorithm     = "aws:kms"
+      kms_master_key_id = aws_kms_key.lab.arn
+    }
+    bucket_key_enabled = true
+  }
+}
@@
-      sse_algorithm = "AES256"
+      sse_algorithm     = "aws:kms"
+      kms_master_key_id = aws_kms_key.lab.arn
```

The second hunk is the log bucket and the trail bucket. Excerpt of `diff -u vulnerable/storage.tf fixed/storage.tf`.
