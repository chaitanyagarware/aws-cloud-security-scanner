variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "trusted_security_principal_arn" {
  type        = string
  description = "Specific trusted security principal allowed to assume this role. Do not use wildcard principals."
}
