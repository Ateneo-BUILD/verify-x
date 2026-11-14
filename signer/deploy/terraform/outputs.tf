output "sns_topic" {
  description = "The policy's [runtime] sns_topic."
  value       = aws_sns_topic.alerts.arn
}

output "ledger_bucket" {
  value = aws_s3_bucket.ledger.id
}

output "iam_user" {
  description = "Make its access key by hand (aws iam create-access-key) and put it in /etc/cl03-signer/credstore/: never in Terraform state."
  value       = aws_iam_user.signer.name
}
