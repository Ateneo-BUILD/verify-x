# The inputs for one Verify site. deploy/deploy.sh fills them from the site
# configuration file (deploy/site.conf.example), so a site has ONE file of
# settings. Run by hand, Terraform reads them from -var or TF_VAR_*.
#
# Every value that is specific to one account, domain or person is required
# and has NO default: a default here would be a setting everybody inherits
# without noticing. No secret is an input, so Terraform state holds none.

variable "aws_account_id" {
  description = "The AWS account this site belongs to. Terraform refuses to touch any other, so credentials for a different account cannot build or change anything there"
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "aws_account_id must be the account's 12-digit id."
  }
}

variable "aws_region" {
  description = "AWS region to build the site in"
  type        = string
}

variable "site_name" {
  description = "Short name for this site, unique in the account: verify for production, verify-test for a second one. Names every resource"
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,23}$", var.site_name))
    error_message = "site_name must be 2 to 24 lower-case letters, digits and hyphens, starting with a letter (load balancer names are built from it)."
  }
}

variable "domain_name" {
  description = "Public host name the site is served on, e.g. verify.example.org"
  type        = string
}

variable "ssh_allowed_cidrs" {
  description = "Address ranges allowed to reach the bastion over SSH, e.g. your office's public address as a /32"
  type        = list(string)

  validation {
    condition     = length(var.ssh_allowed_cidrs) > 0 && alltrue([for c in var.ssh_allowed_cidrs : can(cidrhost(c, 0))])
    error_message = "ssh_allowed_cidrs needs at least one range in CIDR form, e.g. 203.0.113.10/32."
  }
}

variable "ssh_public_key" {
  description = "Public half of the SSH key that deploys use, installed for ec2-user on the bastion and the server"
  type        = string

  validation {
    condition     = can(regex("^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)) ", var.ssh_public_key))
    error_message = "ssh_public_key must be an OpenSSH public key (ssh-ed25519 ..., ssh-rsa ... or ecdsa-sha2-...)."
  }
}

# --- Optional ---

variable "route53_zone_id" {
  description = "Route 53 hosted zone for domain_name. Set it and the certificate's validation record and the site's alias record are created here; leave it empty and create both in your own DNS"
  type        = string
  default     = ""
}

variable "certificate_arn" {
  description = "An existing issued ACM certificate covering domain_name, in this region. Set it to use that instead of requesting a new one"
  type        = string
  default     = ""
}

variable "instance_type" {
  description = "EC2 instance type for the app server"
  type        = string
  default     = "t3.micro"
}

variable "bastion_instance_type" {
  description = "EC2 instance type for the bastion"
  type        = string
  default     = "t3.nano"
}

variable "vpc_cidr" {
  description = "Address range of the VPC this module builds. Change it only if it must not overlap another network you connect to"
  type        = string
  default     = "10.20.0.0/16"
}

variable "root_volume_gb" {
  description = "Size of the app server's encrypted disk, in GB. The database lives on it"
  type        = number
  default     = 30
}

variable "snapshot_retention_days" {
  description = "Daily snapshots of the app server's disk are kept this many days"
  type        = number
  default     = 7
}
