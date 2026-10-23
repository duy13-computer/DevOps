terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

resource "aws_vpc" "lab" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_hostnames = true
  tags = {
    Name = "devsecops-seeded-lab"
  }
}

resource "aws_security_group" "lab" {
  name        = "devsecops-seeded-lab"
  description = "Intentionally insecure scanner fixture; do not apply."
  vpc_id      = aws_vpc.lab.id

  # SEEDED-IAC-01: SSH is exposed to every IPv4 address.
  ingress {
    description = "SEEDED-IAC-01: public SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # SEEDED-IAC-02: RDP is exposed to every IPv4 address.
  ingress {
    description = "SEEDED-IAC-02: public RDP"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# SEEDED-IAC-03: no server-side encryption configuration is enabled.
# SEEDED-IAC-04: a public-read ACL is attached and public access is permitted.
resource "aws_s3_bucket" "lab" {
  bucket_prefix = var.bucket_prefix
  force_destroy = true
}

resource "aws_s3_bucket_ownership_controls" "lab" {
  bucket = aws_s3_bucket.lab.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_public_access_block" "lab" {
  bucket                  = aws_s3_bucket.lab.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_acl" "lab" {
  depends_on = [
    aws_s3_bucket_ownership_controls.lab,
    aws_s3_bucket_public_access_block.lab,
  ]
  bucket = aws_s3_bucket.lab.id
  acl    = "public-read"
}

resource "aws_iam_role" "lab" {
  name = "devsecops-seeded-lab"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

# SEEDED-IAC-05: AdministratorAccess is broader than the lab requires.
resource "aws_iam_role_policy_attachment" "lab_admin" {
  role       = aws_iam_role.lab.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# SEEDED-IAC-06: scanning is disabled and mutable tags are permitted.
resource "aws_ecr_repository" "lab" {
  name                 = var.ecr_repository_name
  image_tag_mutability = "MUTABLE"
  image_scanning_configuration {
    scan_on_push = false
  }
}
