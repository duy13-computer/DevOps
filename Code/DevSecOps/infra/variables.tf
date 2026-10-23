variable "aws_region" {
  description = "AWS region used only when deploying the isolated lab."
  type        = string
  default     = "us-east-1"
}

variable "bucket_prefix" {
  description = "Globally unique prefix for the deliberately weak demo bucket."
  type        = string
  default     = "devsecops-seeded-lab-demo-"
}

variable "ecr_repository_name" {
  description = "Name for the lab's intentionally weak ECR repository."
  type        = string
  default     = "devsecops-seeded-lab"
}
