variable "aws_region" {
  description = "Region used only in configuration. Cape Town. Nothing is deployed."
  type        = string
  default     = "af-south-1"
}

variable "account_id" {
  description = "Placeholder account id from the AWS docs examples. Not an account this lab can access."
  type        = string
  default     = "123456789012"
}

variable "name_prefix" {
  description = "Prefix for lab resource names."
  type        = string
  default     = "cloud-misconfig-lab"
}

variable "ami_id" {
  description = "Placeholder AMI id. RunInstances is never called."
  type        = string
  default     = "ami-0123456789abcdef0"
}

variable "db_password" {
  description = "Planted fake secret. The default is an access-key-shaped string that contains the word NOTREAL. It is not a live credential. The gitleaks allow comment is only on this line, in vulnerable/."
  type        = string
  sensitive   = true
  default     = "AKIA0LABNOTREALKEY99" # gitleaks:allow - obviously fake lab key containing NOTREAL, allowlisted only in vulnerable/variables.tf. Not a real credential.
}
