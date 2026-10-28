# Hardened counterpart of ../vulnerable. This stack is still never applied.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.70"
    }
  }
}

provider "aws" {
  region = var.aws_region

  # validate stays local. These skips stop the provider from looking up
  # credentials, the account id, or the instance metadata service.
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}
