# Vulnerable on purpose. This stack is a static lab: do not run terraform apply.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.70"
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
