# Unencrypted EBS

## What it is

The instance root volume and the extra data volume are both `encrypted = false`.

## Real-world risk

EBS disks and the snapshots taken from them are readable to anyone who can call the snapshot APIs in the account, or who gets a copy of the volume. A stolen snapshot of an unencrypted disk is the disk. Encryption does not stop a live attacker on the instance, but it stops the offline copy.

## Scanner checks

| Scanner | Check | Where |
| --- | --- | --- |
| Checkov | `CKV_AWS_3` | `aws_ebs_volume.data` |
| Checkov | `CKV_AWS_8` | `aws_instance.app` root volume |
| Checkov | `CKV_AWS_189` | data volume is not encrypted with a customer managed key |
| Checkov | `CKV2_AWS_2` | the attached data volume is not encrypted |
| Trivy | `AWS-0026` | data volume encryption, high |
| Trivy | `AWS-0131` | instance block device, high |
| Trivy | `AWS-0027` | data volume is not using a customer managed key, low |

Checkov left these unscored. All of them are 0 in `fixed/`.

## Fix

```diff
--- vulnerable/compute.tf
+++ fixed/compute.tf
@@
   root_block_device {
     volume_type = "gp3"
     volume_size = 20
-    encrypted   = false
+    encrypted   = true
+    kms_key_id  = aws_kms_key.lab.arn
   }
@@
 resource "aws_ebs_volume" "data" {
   availability_zone = aws_subnet.private_a.availability_zone
   size              = 20
   type              = "gp3"
-  encrypted         = false
+  encrypted         = true
+  kms_key_id        = aws_kms_key.lab.arn
```

Excerpt of `diff -u vulnerable/compute.tf fixed/compute.tf`.
