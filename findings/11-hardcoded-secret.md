# Hardcoded fake secret in a variable default

## What it is

`vulnerable/variables.tf` gives `db_password` a default. The value is an access-key-shaped string with the word NOTREAL in it. It is not a live credential, and this lab never authenticates to AWS. The RDS instance in `vulnerable/database.tf` passes that variable through as the master password.

The same line carries `# gitleaks:allow`. That comment is only in `vulnerable/variables.tf`. `fixed/` has no `db_password` variable. The database there uses `manage_master_user_password`, so Terraform would ask AWS to store the password in Secrets Manager. This lab still never applies that.

## Real-world risk

A real password or access key in a default is in git forever, including forks and CI logs. Anyone who can read the repo can use it. A variable with no default, or a password that AWS generates into Secrets Manager, keeps the secret out of the template. The value here is fake on purpose so the lab can show the pattern without shipping a credential.

## Scanner checks

| Scanner | Check | How it was observed |
| --- | --- | --- |
| Checkov | `CKV_SECRET_2` | `checkov-vulnerable.json`, check name "AWS Access Key", on `/variables.tf`. Unscored. Count is 0 in `fixed/`. |
| gitleaks | `aws-access-token` | Not found on the tree that has the allow comment (`gitleaks.json` is `[]`). Found when that comment is removed. See `scan-results/gitleaks-without-allow-comment.json`. |

Trivy config scan does not look for secrets. It did not report this.

Gitleaks' default rules already ignore the AWS documentation example access key (the pattern ends in `EXAMPLE`). That string would not exercise the allow comment, so it is not the value used here.

## Fix

`fixed/variables.tf` deletes the variable. The diff below redacts the default. The real line is only in `vulnerable/variables.tf`.

```diff
--- vulnerable/variables.tf
+++ fixed/variables.tf
@@
-variable "db_password" {
-  description = "Planted fake secret. ..."
-  type        = string
-  sensitive   = true
-  default     = "<NOTREAL access-key-shaped value>" # gitleaks:allow - only on this vulnerable/ line
-}
```

And in `fixed/database.tf`:

```diff
-  password          = var.db_password
+  manage_master_user_password = true
```
