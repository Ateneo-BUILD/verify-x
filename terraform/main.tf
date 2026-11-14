# One Verify site on AWS, built from nothing in a blank account.
#
#                 internet
#                    |
#        +-----------+------------------------------ VPC -----+
#        |  public subnets (two zones)                          |
#        |    load balancer :443 TLS, :80 -> https              |
#        |    bastion (SSH from ssh_allowed_cidrs)              |
#        |    NAT gateway                                       |
#        |                    |                                 |
#        |  private subnet    v                                 |
#        |    app server: nginx :80 -> gunicorn -> Django       |
#        |    (HTTP from the load balancer, SSH from the bastion,|
#        |     outbound through the NAT)                        |
#        +-------------------------------------------------------+
#
# The server provisions itself on first boot from the templates in deploy/;
# deploy/deploy.sh then brings the code, the settings and the key files.
# Its disk, which holds the database, is snapshotted daily.
#
# deploy/deploy.sh runs this with the site's settings and keeps the state
# file beside the site's configuration (`backend "local"` is filled in at
# init), so nothing about a deployment is ever written into this repository.

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "local" {}
}

provider "aws" {
  region = var.aws_region

  # A site lives in an AWS account of its own. With credentials for any other
  # account -- a machine's default profile, say, that belongs to another
  # deployment -- Terraform stops before reading or changing anything.
  allowed_account_ids = [var.aws_account_id]

  default_tags {
    tags = {
      Project = "verify"
      Site    = var.site_name
    }
  }
}

locals {
  app_name = "verify"             # on-disk code directory and the gunicorn wsgi module
  app_user = "ec2-user"           # Amazon Linux 2023's login user; the key pair is installed for it
  app_dir  = "/home/ec2-user/app" # venv/, .env, gunicorn.conf.py, and the code in verify/

  zones = slice(data.aws_availability_zones.available.names, 0, 2)

  app_arch     = contains(data.aws_ec2_instance_type.app.supported_architectures, "arm64") ? "arm64" : "x86_64"
  bastion_arch = contains(data.aws_ec2_instance_type.bastion.supported_architectures, "arm64") ? "arm64" : "x86_64"

  create_certificate = var.certificate_arn == ""
  use_route53        = var.route53_zone_id != ""
  certificate_arn    = local.create_certificate ? aws_acm_certificate_validation.app[0].certificate_arn : var.certificate_arn
}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ec2_instance_type" "app" {
  instance_type = var.instance_type
}

data "aws_ec2_instance_type" "bastion" {
  instance_type = var.bastion_instance_type
}

# The newest Amazon Linux 2023 image, from AWS's public parameter. Both
# servers ignore later changes to it: a new image must never replace the app
# server, whose disk holds the database.
data "aws_ssm_parameter" "app_ami" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-${local.app_arch}"
}

data "aws_ssm_parameter" "bastion_ami" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-${local.bastion_arch}"
}

# --- Network ---------------------------------------------------------------

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.site_name}-vpc" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${var.site_name}-igw" }
}

# Two public subnets because a load balancer must span two zones.
resource "aws_subnet" "public" {
  count = 2

  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone = local.zones[count.index]

  tags = { Name = "${var.site_name}-public-${count.index + 1}" }
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, 10)
  availability_zone = local.zones[0]

  tags = { Name = "${var.site_name}-private" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "${var.site_name}-public" }
}

resource "aws_route_table_association" "public" {
  count = 2

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# The app server reaches out -- packages and Python dependencies on first
# boot, eVerify on every verification -- through this, and nothing reaches in.
resource "aws_eip" "nat" {
  domain = "vpc"

  tags = { Name = "${var.site_name}-nat" }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id

  tags = { Name = "${var.site_name}-nat" }

  depends_on = [aws_internet_gateway.main]
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }

  tags = { Name = "${var.site_name}-private" }
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

# --- Security groups ---------------------------------------------------------

resource "aws_security_group" "alb" {
  name        = "${var.site_name}-alb"
  description = "Load balancer: HTTP and HTTPS from anywhere"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTP, redirected to HTTPS"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.site_name}-alb" }
}

resource "aws_security_group" "bastion" {
  name        = "${var.site_name}-bastion"
  description = "Bastion: SSH from the allowed ranges only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH from ssh_allowed_cidrs"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.ssh_allowed_cidrs
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.site_name}-bastion" }
}

resource "aws_security_group" "app" {
  name        = "${var.site_name}-app"
  description = "App server: HTTP from the load balancer, SSH from the bastion"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "HTTP from the load balancer"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  ingress {
    description     = "SSH from the bastion"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.site_name}-app" }
}

# --- SSH key and bastion ---------------------------------------------------------

resource "aws_key_pair" "deploy" {
  key_name   = "${var.site_name}-deploy"
  public_key = trimspace(var.ssh_public_key)
}

resource "aws_instance" "bastion" {
  ami                    = data.aws_ssm_parameter.bastion_ami.value
  instance_type          = var.bastion_instance_type
  subnet_id              = aws_subnet.public[0].id
  vpc_security_group_ids = [aws_security_group.bastion.id]
  key_name               = aws_key_pair.deploy.key_name

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    volume_size = 8
    volume_type = "gp3"
    encrypted   = true
  }

  tags = { Name = "${var.site_name}-bastion" }

  lifecycle {
    ignore_changes = [ami]
  }
}

# A fixed address, so the bastion keeps it across a stop and start.
resource "aws_eip" "bastion" {
  domain   = "vpc"
  instance = aws_instance.bastion.id

  tags = { Name = "${var.site_name}-bastion" }
}

# --- App server ------------------------------------------------------------------

resource "aws_iam_role" "app" {
  name = "${var.site_name}-server"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Session Manager: a way onto the server from the AWS console even with the
# bastion down.
resource "aws_iam_role_policy_attachment" "app_ssm" {
  role       = aws_iam_role.app.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "app" {
  name = "${var.site_name}-server"
  role = aws_iam_role.app.name
}

resource "aws_instance" "app" {
  ami                    = data.aws_ssm_parameter.app_ami.value
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.app.id]
  key_name               = aws_key_pair.deploy.key_name
  iam_instance_profile   = aws_iam_instance_profile.app.name

  # Provisions the server on its first boot. nginx, the gunicorn unit and
  # gunicorn's config come from deploy/, so the server runs the configuration
  # this repository holds. No secret is in it: user data is readable by
  # anyone allowed to describe the instance. The .env arrives over SSH with
  # the first deploy.
  #
  # Carriage returns are stripped: a Windows checkout can hand these files
  # over with CRLF endings, and a stray \r in a systemd unit or a shell line
  # breaks it on the server with no clue as to why.
  user_data = replace(templatefile("${path.module}/user_data.sh.tftpl", {
    app_user = local.app_user
    app_dir  = local.app_dir
    nginx_conf = trimspace(templatefile("${path.module}/../deploy/nginx.conf.tftpl", {
      app_dir = local.app_dir
    }))
    gunicorn_service = trimspace(templatefile("${path.module}/../deploy/gunicorn.service.tftpl", {
      app_user = local.app_user
      app_dir  = local.app_dir
    }))
    gunicorn_conf = trimspace(file("${path.module}/../deploy/gunicorn.conf.py"))
  }), "\r", "")

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    volume_size           = var.root_volume_gb
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  tags = {
    Name         = "${var.site_name}-server"
    VerifyBackup = var.site_name
  }

  # The database lives on this server's disk, so nothing routine may replace
  # it: not a newer Amazon Linux image, and not an edit to the boot script.
  # A changed template reaches this server by hand (see docs/deploy-aws.md).
  lifecycle {
    ignore_changes = [ami, user_data]
  }
}

# --- Daily snapshots of the app server's disk -----------------------------------

resource "aws_iam_role" "snapshots" {
  name = "${var.site_name}-snapshots"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "dlm.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "snapshots" {
  role       = aws_iam_role.snapshots.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSDataLifecycleManagerServiceRole"
}

resource "aws_dlm_lifecycle_policy" "daily" {
  description        = "${var.site_name}: daily snapshot of the app server"
  execution_role_arn = aws_iam_role.snapshots.arn
  state              = "ENABLED"

  policy_details {
    resource_types = ["INSTANCE"]
    target_tags    = { VerifyBackup = var.site_name }

    schedule {
      name      = "daily"
      copy_tags = true

      create_rule {
        interval      = 24
        interval_unit = "HOURS"
        times         = ["18:00"] # UTC
      }

      retain_rule {
        count = var.snapshot_retention_days
      }
    }
  }
}

# --- Load balancer -----------------------------------------------------------------

resource "aws_lb" "main" {
  name               = "${var.site_name}-alb"
  load_balancer_type = "application"
  internal           = false
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  # nginx and gunicorn allow a request 120 seconds; the default of 60 would
  # cut a slow eVerify call off first.
  idle_timeout               = 180
  drop_invalid_header_fields = true

  tags = { Name = "${var.site_name}-alb" }
}

resource "aws_lb_target_group" "app" {
  name     = "${var.site_name}-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    path                = "/health/"
    port                = "traffic-port"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    matcher             = "200"
  }

  tags = { Name = "${var.site_name}-tg" }
}

resource "aws_lb_target_group_attachment" "app" {
  target_group_arn = aws_lb_target_group.app.arn
  target_id        = aws_instance.app.id
  port             = 80
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = local.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

# --- Certificate and DNS -------------------------------------------------------------

resource "aws_acm_certificate" "app" {
  count = local.create_certificate ? 1 : 0

  domain_name       = var.domain_name
  validation_method = "DNS"

  tags = { Name = "${var.site_name}-cert" }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "validation" {
  for_each = local.create_certificate && local.use_route53 ? {
    for dvo in aws_acm_certificate.app[0].domain_validation_options : dvo.domain_name => dvo
  } : {}

  zone_id         = var.route53_zone_id
  name            = each.value.resource_record_name
  type            = each.value.resource_record_type
  records         = [each.value.resource_record_value]
  ttl             = 300
  allow_overwrite = true
}

# Without Route 53 this waits until the validation record exists in whatever
# DNS serves domain_name. `deploy.sh infra certificate` requests the
# certificate on its own first and prints the record to create.
resource "aws_acm_certificate_validation" "app" {
  count = local.create_certificate ? 1 : 0

  certificate_arn         = aws_acm_certificate.app[0].arn
  validation_record_fqdns = local.use_route53 ? [for r in aws_route53_record.validation : r.fqdn] : null
}

resource "aws_route53_record" "app" {
  count = local.use_route53 ? 1 : 0

  zone_id = var.route53_zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = false
  }
}
