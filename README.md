# cloud-misconfig-lab

[![CI](https://github.com/Lawrence-Flash/cloud-misconfig-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/Lawrence-Flash/cloud-misconfig-lab/actions/workflows/ci.yml)

Two copies of the same small AWS layout. `vulnerable/` has security mistakes planted in the Terraform. `fixed/` is the same layout with those mistakes corrected. Checkov and Trivy scan both copies. A small Python tool prints the before/after counts from the JSON those scanners actually wrote.

Nothing in this repo is deployed. There is no cloud account, no credential, and no `terraform apply`.

## What this is

This is a static-analysis lab. The Terraform is valid enough for `terraform validate`, and invalid on purpose where a security control is missing. The scanners read the files and report the gaps. The fixed copy shows the same resources with the controls turned on, so a reviewer can diff one issue at a time instead of trusting a paragraph that says "I would encrypt that."

The provider region is `af-south-1` (Cape Town). That is only a value in the configuration. Validate does not call AWS.

## Architecture

```text
vulnerable/  -- Checkov + Trivy -->  scan-results/*-vulnerable.json --+
                                                                      +--> python3 -m misconfig report
fixed/       -- Checkov + Trivy -->  scan-results/*-fixed.json      --+--> docs/scan-summary.md

GitHub Actions
  terraform fmt / init -backend=false / validate
  Checkov and Trivy on both folders
  gate: vulnerable must have findings; fixed must not have critical or high
  gitleaks, CodeQL (Python), unit tests, SARIF upload for fixed/
```

`findings/` is one note per planted issue: what it is, the practical risk, the check ids that showed up in the JSON, and the diff. Ids that a scanner did not print are not listed there.

## Quick start

From WSL or any Linux shell, at the repo root. Pinned versions that produced the committed JSON are in `scan-results/tool-versions.txt` (Terraform 1.13.4, Checkov 3.2.449, Trivy 0.76.1, gitleaks 8.24.2).

```bash
python3 -m pip install --user -r requirements-scanners.txt

terraform fmt -check -recursive
terraform -chdir=vulnerable init -backend=false -input=false
terraform -chdir=vulnerable validate
terraform -chdir=fixed init -backend=false -input=false
terraform -chdir=fixed validate

checkov -d vulnerable --framework terraform --framework secrets \
  --download-external-modules false --soft-fail
checkov -d fixed --framework terraform --framework secrets \
  --download-external-modules false --soft-fail

trivy config vulnerable/
trivy config fixed/

python3 -m unittest discover -s tests -v
python3 -m misconfig report
```

`python3 -m misconfig report` reads `scan-results/` and writes `docs/scan-summary.md`. It uses the Python standard library only. Checkov is not imported.

`bash scripts/scan.sh` runs fmt, validate, both scanners, gitleaks, the report, and the gate. It expects `terraform`, `checkov`, `trivy`, and `gitleaks` on `PATH`. Install Trivy and gitleaks from their GitHub releases if you want the same versions as CI. Do not run `terraform apply`.

## Before and after

These counts are failed check instances from the JSON committed in `scan-results/`. One resource failing one check counts as 1. Checkov 3.2.449 left `severity` null in this open-source run, so those rows are `unscored`. I did not look up a severity and fill it in. Trivy 0.76.1 printed its own severities.

| Scanner | Severity | Vulnerable | Fixed |
| --- | --- | ---: | ---: |
| Checkov | CRITICAL | 0 | 0 |
| Checkov | HIGH | 0 | 0 |
| Checkov | unscored | 57 | 10 |
| Trivy | CRITICAL | 1 | 0 |
| Trivy | HIGH | 16 | 0 |
| Trivy | MEDIUM | 6 | 0 |
| Trivy | LOW | 4 | 0 |

Totals: Checkov 57 vulnerable, 10 fixed. Trivy 27 vulnerable, 0 fixed.

The 10 Checkov rows still failing in `fixed/` are unscored. They are cross-region replication on the three buckets (`CKV_AWS_144`), S3 event notifications on the three buckets (`CKV2_AWS_62`), a CloudTrail SNS topic (`CKV_AWS_252`), and the KMS key policy (`CKV_AWS_109`, `CKV_AWS_111`, `CKV_AWS_356`). This lab stays in one region and does not add a second bucket, an event destination, or an SNS topic. A KMS key policy uses `*` as its resource. Trivy reported none of those as failed checks on `fixed/`. The full check-by-check table is `docs/scan-summary.md`.

## Findings

| Issue | Note |
| --- | --- |
| Public S3 bucket and a public access block that is off | [findings/01-public-s3.md](findings/01-public-s3.md) |
| S3 encryption missing, or SSE-S3 instead of a customer key | [findings/02-unencrypted-s3.md](findings/02-unencrypted-s3.md) |
| Unencrypted root volume and data volume | [findings/03-unencrypted-ebs.md](findings/03-unencrypted-ebs.md) |
| SSH and RDP from `0.0.0.0/0`, plus open egress | [findings/04-open-security-group.md](findings/04-open-security-group.md) |
| RDS public, unencrypted, backups off | [findings/05-rds.md](findings/05-rds.md) |
| IAM `Action "*"` and `Resource "*"` | [findings/06-iam-wildcard.md](findings/06-iam-wildcard.md) |
| No access logs or versioning on the data bucket | [findings/07-s3-logging-versioning.md](findings/07-s3-logging-versioning.md) |
| CloudTrail in one region, log validation off | [findings/08-cloudtrail.md](findings/08-cloudtrail.md) |
| KMS rotation off | [findings/09-kms-rotation.md](findings/09-kms-rotation.md) |
| IMDSv1 allowed | [findings/10-imdsv1.md](findings/10-imdsv1.md) |
| Fake secret in a variable default | [findings/11-hardcoded-secret.md](findings/11-hardcoded-secret.md) |

## CI

`.github/workflows/ci.yml` does the following.

- `terraform fmt -check`, `terraform init -backend=false`, and `terraform validate` on `vulnerable/` and `fixed/`.
- Checkov 3.2.449 on both. Findings in `vulnerable/` do not fail the job. The job does fail if `vulnerable/` comes back with zero findings. `fixed/` fails only when a failed check is critical or high, or when a critical or high check is skipped without a justification comment.
- Trivy 0.76.1 config scan on both, with the same rule.
- `python3 -m unittest discover -s tests -v`, then a check that `docs/scan-summary.md` still matches the committed JSON.
- gitleaks 8.24.2 on git history and on the working tree. The planted value is allowlisted only by the `# gitleaks:allow` comment on its line in `vulnerable/variables.tf`.
- CodeQL for Python.
- SARIF upload of the Checkov and Trivy results for `fixed/`, for the code scanning tab. That upload is free on a public repository. It needs the default `GITHUB_TOKEN` `security-events: write` permission, which the workflow sets. It does not use a paid feature.

Dependabot is configured for GitHub Actions and for the Terraform in both folders (`.github/dependabot.yml`).

## Limitations

- This is static analysis of Terraform. It does not prove a live account is safe, and it does not see resources created outside these files.
- Nothing is deployed. `terraform validate` does not talk to AWS. `skip_credentials_validation`, `skip_requesting_account_id`, and `skip_metadata_api_check` are set so the provider does not look for credentials during validate.
- The lab is AWS only.
- Checkov and Trivy do not flag the same set. The IAM wildcard is a Checkov result. Trivy did not report it. Trivy rated open egress critical. Checkov reported that check and did not score it.
- Ten Checkov checks remain in `fixed/` and are unscored. They are described above. They are not hidden with skip comments.
- A later Trivy checks bundle can flag something this snapshot did not. CI scans again. The numbers in this README are the committed JSON, not a promise about next month's rules.
- The fake secret is shaped like an access key so the scanners have a pattern to match. It contains the word NOTREAL. It is not a credential.

## What I learned

I wanted the mistake and the fix in the same pull request, with the scanner output saved, so the counts were not something I typed from memory.

Checkov 3.2.449, without a Prisma API key, wrote `"severity": null` on every failed check. Calling those rows high would have been me, not the tool. Trivy 0.76.1 did assign critical, high, medium, and low. The CI gate uses that. A Checkov row with no severity does not fail the high/critical gate, and the table says `unscored` so that limit is visible.

The two tools do not overlap cleanly. Checkov reported the admin IAM policy as nine checks. The Trivy config scan reported none of them. I would have overclaimed if the finding note listed a Trivy id I had not seen. Trivy rated `0.0.0.0/0` egress critical, which is harsher than the SSH and RDP findings. I had planted port 22 and 3389. The egress rule was the one Trivy put at the top.

A public access block is four switches. Setting the resource and leaving every flag false is not a control. The scanners reported each switch.

Gitleaks already ignores the AWS documentation example access key, because that pattern ends in `EXAMPLE`. An allow comment on that string does nothing useful. I used a different string that is obviously not a real key, and the allow comment is only on that one line. A path allowlist for all of `vulnerable/` would hide a real secret added later. With the comment removed, gitleaks reports `aws-access-token`. With the comment present, the repo scan is empty.

`fixed/` is not an empty report. Ten Checkov checks still fail. They want a second region, bucket event notifications, an SNS topic on the trail, and a KMS key policy that does not use `*`. I left them in the table. Skipping them to force a zero would make the after column look cleaner than the scan was.

None of this was deployed. A green scan of `fixed/` means these templates look right to these two scanners. It does not mean an account is safe.

## License

MIT. See [LICENSE](LICENSE).
