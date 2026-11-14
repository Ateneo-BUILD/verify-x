# deploy/deploy.sh reads bastion_public_ip and server_private_ip on every
# run, so a site's addresses are never written down anywhere.

output "app_url" {
  description = "The site's address"
  value       = "https://${var.domain_name}"
}

output "alb_dns_name" {
  description = "Point domain_name at this (a CNAME) unless route53_zone_id is set"
  value       = aws_lb.main.dns_name
}

output "acm_validation_records" {
  description = "DNS records that prove you own domain_name; create them unless route53_zone_id or certificate_arn is set"
  value = local.create_certificate ? {
    for dvo in aws_acm_certificate.app[0].domain_validation_options : dvo.domain_name => {
      name  = dvo.resource_record_name
      type  = dvo.resource_record_type
      value = dvo.resource_record_value
    }
  } : {}
}

output "bastion_public_ip" {
  description = "The bastion's fixed public address; deploys and SSH sessions go through it"
  value       = aws_eip.bastion.public_ip
}

output "server_private_ip" {
  description = "The app server's address inside the VPC"
  value       = aws_instance.app.private_ip
}

output "bastion_instance_id" {
  description = "The bastion's EC2 instance id; deploy.sh hostkeys reads its SSH host keys from its console"
  value       = aws_instance.bastion.id
}

output "server_instance_id" {
  description = "The app server's EC2 instance id"
  value       = aws_instance.app.id
}

output "aws_account_id" {
  description = "The AWS account the site is built in"
  value       = var.aws_account_id
}

output "aws_region" {
  description = "Region the site is built in"
  value       = var.aws_region
}
