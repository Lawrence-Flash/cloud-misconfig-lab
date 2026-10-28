# Public S3 bucket

## What it is

The lab data bucket is world-readable. Ownership controls leave ACLs enabled, the canned ACL is `public-read`, and a bucket policy allows `s3:GetObject` for principal `*`. The public access block exists, but all four switches are off, so it does not block that ACL or that policy.

## Real-world risk

Anyone who can reach the bucket name can read the objects. A public access block is the account-side brake on a bad ACL or a bad bucket policy. With the switches off, one wildcard principal is enough to expose backups, exports, or logs. This is the class of mistake behind a long list of public-bucket incidents.

## Scanner checks

Observed on the vulnerable data bucket. Counts are in `docs/scan-summary.md`.

| Scanner | Check | What it flagged |
| --- | --- | --- |
| Checkov | `CKV_AWS_20` | Public-read ACL |
| Checkov | `CKV_AWS_53` | `block_public_acls` is off |
| Checkov | `CKV_AWS_54` | `block_public_policy` is off |
| Checkov | `CKV_AWS_55` | `ignore_public_acls` is off |
| Checkov | `CKV_AWS_56` | `restrict_public_buckets` is off |
| Checkov | `CKV2_AWS_6` | Public access block does not actually block public access |
| Checkov | `CKV2_AWS_65` | ACLs are still enabled (`ObjectWriter`) |
| Checkov | `CKV_AWS_379` | The public ACL resource has no deny for insecure transport |
| Trivy | `AWS-0086` | Block public ACL is off |
| Trivy | `AWS-0087` | Block public policy is off |
| Trivy | `AWS-0091` | Ignore public ACLs is off |
| Trivy | `AWS-0092` | Bucket is publicly readable through an ACL |
| Trivy | `AWS-0093` | Restrict public buckets is off |

Checkov left every one of these unscored. Trivy rated `AWS-0086`, `AWS-0087`, `AWS-0091`, `AWS-0092`, and `AWS-0093` high. All of them are 0 in `fixed/`.

## Fix

`fixed/storage.tf` turns ACLs off, turns all four public-access switches on, deletes the public ACL, and replaces the anonymous allow with a deny for HTTP.

```diff
--- vulnerable/storage.tf
+++ fixed/storage.tf
@@
-    object_ownership = "ObjectWriter"
+    object_ownership = "BucketOwnerEnforced"
@@
-resource "aws_s3_bucket_acl" "data" {
-  bucket = aws_s3_bucket.data.id
-  acl    = "public-read"
-}
-
-resource "aws_s3_bucket_public_access_block" "data" {
-  bucket = aws_s3_bucket.data.id
-
-  block_public_acls       = false
-  block_public_policy     = false
-  ignore_public_acls      = false
-  restrict_public_buckets = false
-}
+resource "aws_s3_bucket_public_access_block" "data" {
+  bucket = aws_s3_bucket.data.id
+
+  block_public_acls       = true
+  block_public_policy     = true
+  ignore_public_acls      = true
+  restrict_public_buckets = true
+}
@@
-    sid     = "PublicRead"
-    effect  = "Allow"
-    actions = ["s3:GetObject"]
+    sid     = "DenyInsecureTransport"
+    effect  = "Deny"
+    actions = ["s3:*"]
```

Excerpt of `diff -u vulnerable/storage.tf fixed/storage.tf`.
