# The credential signer's AWS side, for a site whose signer ships its ledger
# to S3 (signer/deploy/README.md, "Install"): the ledger bucket, the alert
# topic and its email, the IAM user the signer reaches them with, and the
# alarms on its heartbeat. A root of its own: nothing here touches the
# instance, and a development site with `ledger_dir` needs none of it.
#
# The IAM user's access key is made by hand afterwards and put in
# /etc/cl03-signer/credstore/, so it is never in Terraform state.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

locals {
  prefix = coalesce(var.ledger_prefix, var.site)
  name   = "cl03-signer-${var.site}"
}

# -- the ledger: written once and kept ledger_retain_days (policy.toml, 400) -

resource "aws_s3_bucket" "ledger" {
  bucket              = var.ledger_bucket
  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "ledger" {
  bucket = aws_s3_bucket.ledger.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "ledger" {
  bucket = aws_s3_bucket.ledger.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.retain_days
    }
  }
}

resource "aws_s3_bucket_public_access_block" "ledger" {
  bucket                  = aws_s3_bucket.ledger.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ledger" {
  bucket = aws_s3_bucket.ledger.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# -- alerts: SNS email ----------------------------------------------------------

resource "aws_sns_topic" "alerts" {
  name = local.name
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# -- the signer's own IAM user, not the instance role ---------------------------
#
# The app user could reach the instance role through IMDS; only cl03-signer can
# read this user's key. PutObjectRetention because every object is written
# with its own compliance retention (aws.S3Uploader).

resource "aws_iam_user" "signer" {
  name = local.name
}

resource "aws_iam_user_policy" "signer" {
  name = "${local.name}-ledger-alerts-metrics"
  user = aws_iam_user.signer.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:PutObjectRetention", "s3:GetObject"]
        Resource = "${aws_s3_bucket.ledger.arn}/${local.prefix}/*"
      },
      {
        Effect    = "Allow"
        Action    = "s3:ListBucket"
        Resource  = aws_s3_bucket.ledger.arn
        Condition = { StringLike = { "s3:prefix" = ["${local.prefix}/*"] } }
      },
      {
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.alerts.arn
      },
      {
        Effect    = "Allow"
        Action    = "cloudwatch:PutMetricData"
        Resource  = "*"
        Condition = { StringEquals = { "cloudwatch:namespace" = var.metric_namespace } }
      },
    ]
  })
}

# -- alarms on the heartbeat (signer/aws.py Heartbeat, every ship_every_seconds) -

resource "aws_cloudwatch_metric_alarm" "alive" {
  alarm_name          = "${local.name}-alive"
  alarm_description   = "The signer has sent no heartbeat: it is down, or cannot reach CloudWatch. Missing data is a breach."
  namespace           = var.metric_namespace
  metric_name         = "Alive"
  dimensions          = { Site = var.site }
  statistic           = "Sum"
  period              = 600
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "failing" {
  alarm_name          = "${local.name}-failing"
  alarm_description   = "The signer answers but its operations keep failing (internal failures in a row): journalctl -u cl03-signer."
  namespace           = var.metric_namespace
  metric_name         = "Failing"
  dimensions          = { Site = var.site }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "paused" {
  alarm_name          = "${local.name}-paused"
  alarm_description   = "Something is paused on the signer: cl03signer status. Resuming is an operator's."
  namespace           = var.metric_namespace
  metric_name         = "Paused"
  dimensions          = { Site = var.site }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}
