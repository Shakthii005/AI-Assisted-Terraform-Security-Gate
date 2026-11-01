
# Day 1: Basic Terraform S3 security scanning test

terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

# AWS provider configuration
provider "aws" {
  region = "ap-south-1"
}

# Basic S3 bucket for our first security scan
resource "aws_s3_bucket" "day1_demo" {
  bucket = "ai-assisted-terraform-security-gate-day1-demo"

  tags = {
    Name        = "Day1-Security-Scan-Demo"
    Environment = "Learning"
  }
}
