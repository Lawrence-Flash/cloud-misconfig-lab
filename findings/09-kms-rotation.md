# KMS key rotation is off

## What it is

`aws_kms_key.lab` sets `enable_key_rotation = false`. The key still exists in the vulnerable stack. It is just not set to rotate. In `fixed/` the same key has rotation on, and the data bucket, both EBS volumes, the database, CloudTrail, and the CloudWatch log group use it.

## Real-world risk

A customer managed key that never rotates keeps the same key material for as long as the key lives. If that material is exposed, every object encrypted under it stays exposed until you re-encrypt. Automatic rotation does not re-encrypt old objects by itself. It limits how long newly encrypted data uses the old material, and it is the control both scanners asked for.

## Scanner checks

| Scanner | Check | Severity in the JSON |
| --- | --- | --- |
| Checkov | `CKV_AWS_7` | unscored |
| Trivy | `AWS-0065` | medium |

Both are on `aws_kms_key.lab` and both are 0 in `fixed/`.

Checkov also reports `CKV_AWS_109`, `CKV_AWS_111`, and `CKV_AWS_356` on the key policy in both copies, because the policy uses `kms:*` and `resources = ["*"]`. Those are not the rotation check. They stay in `fixed/`. A key policy's resource element is `*`.

## Fix

```diff
--- vulnerable/logging.tf
+++ fixed/logging.tf
@@
-  # PLANTED: automatic annual rotation is off.
-  enable_key_rotation = false
+  # FIXED: AWS rotates the key material automatically once a year.
+  enable_key_rotation = true
```

Excerpt of `diff -u vulnerable/logging.tf fixed/logging.tf`.
