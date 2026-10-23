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

data "aws_caller_identity" "current" {}

resource "aws_vpc" "lab" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_hostnames = true
  tags = {
    Name = "devsecops-seeded-lab"
  }
}

resource "aws_default_security_group" "lab" {
  vpc_id  = aws_vpc.lab.id
  ingress = []
  egress  = []
}

resource "aws_security_group" "lab" {
  name        = "devsecops-seeded-lab"
  description = "Restricted management access for the isolated lab."
  vpc_id      = aws_vpc.lab.id

  #checkov:skip=CKV2_AWS_5: This scanner-only lab exports the group for external test workloads and does not create compute resources.

  # Management access is limited to the configured private CIDR.
  ingress {
    description = "SSH from the approved management network"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.management_cidr]
  }

  # RDP is limited to the configured private CIDR.
  ingress {
    description = "RDP from the approved management network"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = [var.management_cidr]
  }

  egress = []
}

# This disposable single-region lab has no cross-region recovery or event-driven
# consumer. The bucket is versioned, encrypted, and has a bounded retention period.
resource "aws_s3_bucket" "lab" {
  bucket_prefix = var.bucket_prefix
  force_destroy = true

  #checkov:skip=CKV_AWS_18: The disposable lab bucket contains no production data; access logging is out of scope.
  #checkov:skip=CKV_AWS_144: This single-region demonstration has no disaster-recovery requirement.
  #checkov:skip=CKV2_AWS_62: No event-driven consumer is configured for this lab bucket.
}

resource "aws_kms_key" "lab_s3" {
  description             = "Encrypt DevSecOps lab bucket objects"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "lab_s3" {
  name          = "alias/devsecops-lab-s3"
  target_key_id = aws_kms_key.lab_s3.key_id
}

resource "aws_s3_bucket_server_side_encryption_configuration" "lab" {
  bucket = aws_s3_bucket.lab.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.lab_s3.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_ownership_controls" "lab" {
  bucket = aws_s3_bucket.lab.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "lab" {
  bucket                  = aws_s3_bucket.lab.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "lab" {
  bucket = aws_s3_bucket.lab.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "lab" {
  bucket = aws_s3_bucket.lab.id
  rule {
    id     = "expire-lab-data"
    status = "Enabled"
    filter {}
    expiration {
      days = 90
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_kms_key" "flow_logs" {
  description             = "Encrypt DevSecOps lab VPC flow logs"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableAccountAdministration"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCloudWatchLogs"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.aws_region}.amazonaws.com" }
        Action    = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
        Resource  = "*"
        Condition = {
          ArnEquals = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/devsecops/lab/vpc-flow-logs"
          }
        }
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/devsecops/lab/vpc-flow-logs"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.flow_logs.arn
}

resource "aws_iam_role" "flow_logs" {
  name = "devsecops-lab-flow-logs"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnLike = {
          "aws:SourceArn" = "arn:aws:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:vpc-flow-log/*"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "devsecops-lab-flow-logs-write"
  role = aws_iam_role.flow_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.flow_logs.arn}:*"
      },
      {
        Effect   = "Allow"
        Action   = ["logs:DescribeLogGroups"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["logs:DescribeLogStreams"]
        Resource = "${aws_cloudwatch_log_group.flow_logs.arn}:*"
      }
    ]
  })
}

resource "aws_flow_log" "lab" {
  iam_role_arn         = aws_iam_role.flow_logs.arn
  log_destination      = aws_cloudwatch_log_group.flow_logs.arn
  log_destination_type = "cloud-watch-logs"
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.lab.id
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

resource "aws_iam_role_policy" "lab_runtime" {
  name = "devsecops-lab-runtime"
  role = aws_iam_role.lab.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "arn:aws:logs:${var.aws_region}:*:log-group:/devsecops/lab:*"
    }]
  })
}

resource "aws_ecr_repository" "lab" {
  name                 = var.ecr_repository_name
  image_tag_mutability = "IMMUTABLE"
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.ecr.arn
  }
  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_kms_key" "ecr" {
  description             = "Encrypt DevSecOps lab container images"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "EnableAccountAdministration"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })
}
