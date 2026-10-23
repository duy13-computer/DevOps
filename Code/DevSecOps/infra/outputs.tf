output "lab_vpc_id" {
  description = "VPC created for the isolated lab."
  value       = aws_vpc.lab.id
}

output "lab_security_group_id" {
  description = "Security group scanned by Checkov and Conftest."
  value       = aws_security_group.lab.id
}

output "lab_bucket_name" {
  description = "Public-read demo bucket name."
  value       = aws_s3_bucket.lab.bucket
}

output "lab_ecr_repository_url" {
  description = "ECR repository URL for image scan/signing demonstrations."
  value       = aws_ecr_repository.lab.repository_url
}
