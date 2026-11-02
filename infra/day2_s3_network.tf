
# ============================================================
# DAY 2 - FICTIONAL COMPANY INFRASTRUCTURE
# INTENTIONALLY VULNERABLE - DO NOT DEPLOY
# ============================================================

# -------------------- S3 STORAGE --------------------

resource "aws_s3_bucket" "company_data" {
  bucket = "ai-assisted-tf-gate-company-data-day2-demo-2026"

  tags = {
    Name        = "Company-Data-Bucket"
    Environment = "Learning"
  }
}

# VULNERABILITY 1: Public bucket ACL
resource "aws_s3_bucket_ownership_controls" "company_data" {
  bucket = aws_s3_bucket.company_data.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "company_data" {
  depends_on = [
    aws_s3_bucket_ownership_controls.company_data
  ]

  bucket = aws_s3_bucket.company_data.id
  acl    = "public-read"
}

# VULNERABILITY 2: No server-side encryption configuration
# VULNERABILITY 3: No bucket versioning configuration
# VULNERABILITY 4: No access logging configuration
# VULNERABILITY 5: No public access block configuration


# -------------------- NETWORK / VPC --------------------

resource "aws_vpc" "company" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "Company-VPC"
  }
}

resource "aws_subnet" "app_a" {
  vpc_id                  = aws_vpc.company.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "ap-south-1a"
  map_public_ip_on_launch = true

  tags = {
    Name = "Company-App-Subnet-A"
  }
}

resource "aws_subnet" "db_b" {
  vpc_id            = aws_vpc.company.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "ap-south-1b"

  tags = {
    Name = "Company-DB-Subnet-B"
  }
}

# VULNERABILITY 6: SSH accessible from the entire internet
resource "aws_security_group" "ssh_open" {
  name        = "company-ssh-open"
  description = "Intentionally vulnerable SSH rule"
  vpc_id      = aws_vpc.company.id

  ingress {
    description = "SSH open to the world"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Company-SSH-Open"
  }
}

# VULNERABILITY 7: RDP accessible from the entire internet
resource "aws_security_group" "rdp_open" {
  name        = "company-rdp-open"
  description = "Intentionally vulnerable RDP rule"
  vpc_id      = aws_vpc.company.id

  ingress {
    description = "RDP open to the world"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Company-RDP-Open"
  }
}

# VULNERABILITY 8: All inbound ports open to the internet
resource "aws_security_group" "all_ports_open" {
  name        = "company-all-ports-open"
  description = "Intentionally vulnerable unrestricted ingress"
  vpc_id      = aws_vpc.company.id

  ingress {
    description = "All protocols open to the world"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Company-All-Ports-Open"
  }
}

# VULNERABILITY 9: Default security group allows internet ingress
resource "aws_default_security_group" "company_default" {
  vpc_id = aws_vpc.company.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# VULNERABILITY 10: No VPC Flow Logs resource configured
