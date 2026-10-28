# IMDSv1 is allowed on the instance

## What it is

`metadata_options.http_tokens` is `optional`. The metadata service answers both the old request style (IMDSv1) and the session-token style (IMDSv2). The endpoint is enabled, which is normal. The token requirement is the control.

## Real-world risk

IMDSv1 returns the instance role credentials to any process on the host that can make a simple HTTP request to the metadata address. A server-side request forgery bug in an app on that host can do it too, because IMDSv1 does not require a session token or a hop-limit trick beyond the default. Those credentials are the role from `iam.tf`. In the vulnerable stack that role is `*`. IMDSv2 refuses the request unless the caller first obtains a token with a PUT.

## Scanner checks

| Scanner | Check | Severity in the JSON |
| --- | --- | --- |
| Checkov | `CKV_AWS_79` | unscored |
| Trivy | `AWS-0028` | high |

Both are on `aws_instance.app` and both are 0 in `fixed/`.

## Fix

```diff
--- vulnerable/compute.tf
+++ fixed/compute.tf
@@
   metadata_options {
     http_endpoint               = "enabled"
-    http_tokens                 = "optional"
+    http_tokens                 = "required"
     http_put_response_hop_limit = 1
   }
```

Excerpt of `diff -u vulnerable/compute.tf fixed/compute.tf`.
