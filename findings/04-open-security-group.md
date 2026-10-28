# Security group open to SSH, RDP, and all egress

## What it is

`aws_security_group_rule.app_ssh` allows TCP 22 from `0.0.0.0/0`. `app_rdp` does the same for TCP 3389. `app_egress_all` allows every protocol out to `0.0.0.0/0`. The instance is in a private subnet, but the rules themselves are wide open. A later change that gives the instance a public address, or a route that should not exist, inherits these rules.

## Real-world risk

Port 22 and 3389 are the two ports scanners and botnets try first. An open rule is an invitation to guess passwords or reuse stolen ones. Unrestricted egress matters because a process that is already on the instance can talk to anywhere, which is how stolen data leaves and how a callback is made. Trivy rated the egress rule critical, higher than the SSH and RDP rules.

## Scanner checks

| Scanner | Check | Where |
| --- | --- | --- |
| Checkov | `CKV_AWS_24` | SSH from `0.0.0.0/0` |
| Checkov | `CKV_AWS_25` | RDP from `0.0.0.0/0` |
| Checkov | `CKV_AWS_382` | egress to `0.0.0.0/0` on all ports |
| Trivy | `AWS-0107` | SSH rule and RDP rule, high, counted twice |
| Trivy | `AWS-0104` | unrestricted egress, critical |

All of them are 0 in `fixed/`.

## Fix

```diff
--- vulnerable/compute.tf
+++ fixed/compute.tf
@@
-  description       = "SSH from anywhere"
+  description       = "SSH from inside the lab VPC"
   from_port         = 22
   to_port           = 22
   protocol          = "tcp"
-  cidr_blocks       = ["0.0.0.0/0"]
+  cidr_blocks       = ["10.0.0.0/16"]
@@
-resource "aws_security_group_rule" "app_rdp" {
-  type              = "ingress"
-  description       = "RDP from anywhere"
-  from_port         = 3389
-  to_port           = 3389
-  protocol          = "tcp"
-  cidr_blocks       = ["0.0.0.0/0"]
-  security_group_id = aws_security_group.app.id
-}
-
-resource "aws_security_group_rule" "app_egress_all" {
-  cidr_blocks       = ["0.0.0.0/0"]
-  protocol          = "-1"
-}
+resource "aws_security_group_rule" "app_egress_mysql" {
+  description              = "MySQL to the database security group"
+  from_port                = 3306
+  to_port                  = 3306
+  protocol                 = "tcp"
+  source_security_group_id = aws_security_group.db.id
+}
```

Excerpt of `diff -u vulnerable/compute.tf fixed/compute.tf`. RDP is removed. Egress is only MySQL to the database security group.
