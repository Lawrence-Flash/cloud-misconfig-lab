# CloudTrail is single-region and does not validate logs

## What it is

A trail exists. It is not missing. `is_multi_region_trail` and `include_global_service_events` are false, so events outside `af-south-1` and global service events are not in this trail. `enable_log_file_validation` is false, so a deleted or edited log object will not fail a digest check. The trail is also not encrypted with the customer managed key, and it does not send a copy to CloudWatch Logs.

`CKV_AWS_252` (CloudTrail should define an SNS topic) is reported on both copies. `fixed/` does not add a topic. That check stays at 1. It is listed with the other residuals in `docs/scan-summary.md`.

## Real-world risk

A single-region trail is a blind spot everywhere else you create resources. IAM is a global service, so a trail that skips global events misses `CreateUser` and `AttachRolePolicy` unless some other trail records them. Without log-file validation you cannot show that the objects in the bucket are the objects CloudTrail wrote. An attacker who can change the bucket can change the history.

## Scanner checks

On `aws_cloudtrail.lab` in the vulnerable scan:

| Scanner | Check | What it flagged |
| --- | --- | --- |
| Checkov | `CKV_AWS_67` | not all regions |
| Checkov | `CKV_AWS_36` | log file validation off |
| Checkov | `CKV_AWS_35` | trail logs not encrypted with a customer managed key |
| Checkov | `CKV2_AWS_10` | trail not integrated with CloudWatch Logs |
| Trivy | `AWS-0014` | not all regions, medium |
| Trivy | `AWS-0016` | log validation off, high |
| Trivy | `AWS-0015` | trail not using a customer managed key, high |
| Trivy | `AWS-0162` | logs not also sent to CloudWatch, low |

Those eight are 0 in `fixed/`. `CKV_AWS_252` is not in that list of fixes. It is still failing.

## Fix

```diff
--- vulnerable/logging.tf
+++ fixed/logging.tf
@@
-  is_multi_region_trail         = false
-  enable_log_file_validation    = false
-  include_global_service_events = false
+  is_multi_region_trail         = true
+  enable_log_file_validation    = true
+  include_global_service_events = true
   enable_logging                = true
+  kms_key_id                    = aws_kms_key.lab.arn
+  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.trail.arn}:*"
+  cloud_watch_logs_role_arn     = aws_iam_role.trail_logs.arn
```

Excerpt of `diff -u vulnerable/logging.tf fixed/logging.tf`. The fixed file also adds the log group and the role that the trail writes to.
