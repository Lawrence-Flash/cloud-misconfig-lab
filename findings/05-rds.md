# RDS publicly accessible, unencrypted, and not backed up

## What it is

`aws_db_instance.lab` in `vulnerable/` sets `publicly_accessible = true`, `storage_encrypted = false`, and `backup_retention_period = 0`. The database security group only allows MySQL from the application group, so the public flag is not the same thing as an open port. It still puts the instance on a public address when the subnets allow it. Backups are off, so there is no automated restore point. The disk is not encrypted.

The same resource also leaves out deletion protection, Multi-AZ, IAM authentication, log exports, minor-version upgrades, enhanced monitoring, copy-tags-to-snapshot, and Performance Insights. Those were not the three planted settings. The scanners reported them on this instance anyway, and `fixed/database.tf` turns them on.

## Real-world risk

A publicly accessible database is one security-group change away from the internet. Unencrypted storage means a snapshot is readable without a key. `backup_retention_period = 0` means a bad deploy or a dropped table has nothing to restore. Deletion protection is the last prompt before `destroy` removes the instance.

## Scanner checks

On `aws_db_instance.lab` in the vulnerable scan:

| Scanner | Check | Planted setting or related control |
| --- | --- | --- |
| Checkov | `CKV_AWS_17` | publicly accessible |
| Checkov | `CKV_AWS_16` | storage encryption |
| Checkov | `CKV_AWS_133` | backup retention |
| Checkov | `CKV_AWS_293` | deletion protection |
| Checkov | `CKV_AWS_157` | Multi-AZ |
| Checkov | `CKV_AWS_161` | IAM database authentication |
| Checkov | `CKV_AWS_129` | database logs |
| Checkov | `CKV_AWS_226` | minor version upgrades |
| Checkov | `CKV_AWS_118` | enhanced monitoring |
| Checkov | `CKV2_AWS_60` | copy tags to snapshots |
| Trivy | `AWS-0180` | publicly accessible, high |
| Trivy | `AWS-0080` | encryption, high |
| Trivy | `AWS-0077` | backup retention, medium |
| Trivy | `AWS-0177` | deletion protection, medium |
| Trivy | `AWS-0176` | IAM authentication, medium |
| Trivy | `AWS-0133` | Performance Insights, low |

Checkov left its RDS checks unscored. All of the ids above are 0 in `fixed/`.

## Fix

```diff
--- vulnerable/database.tf
+++ fixed/database.tf
@@
-  password          = var.db_password
+  manage_master_user_password = true
@@
-  publicly_accessible     = true
-  storage_encrypted       = false
-  backup_retention_period = 0
-  skip_final_snapshot     = true
-  deletion_protection     = false
-  multi_az                = false
+  publicly_accessible                 = false
+  storage_encrypted                   = true
+  kms_key_id                          = aws_kms_key.lab.arn
+  backup_retention_period             = 7
+  deletion_protection                 = true
+  multi_az                            = true
```

`fixed/` also sets the log exports, IAM authentication, enhanced monitoring, and Performance Insights that the scanners asked for. The master password is no longer a Terraform variable. Excerpt of `diff -u vulnerable/database.tf fixed/database.tf`.
