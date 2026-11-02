
# ============================================================
# DAY 2 - EC2, EBS AND RDS
# INTENTIONALLY VULNERABLE - DO NOT DEPLOY
# ============================================================

# -------------------- EC2 --------------------

resource "aws_instance" "company_app" {
  ami                         = "ami-0c1ac8a41498c1a9c"
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.app_a.id
  vpc_security_group_ids      = [aws_security_group.ssh_open.id]
  associate_public_ip_address = true

  # VULNERABILITY 11: IMDSv1 is allowed
  metadata_options {
    http_tokens = "optional"
  }

  # VULNERABILITY 12: Root volume is not encrypted
  root_block_device {
    volume_size = 8
    volume_type = "gp3"
    encrypted   = false
  }

  tags = {
    Name = "Company-App-Server"
  }
}

# -------------------- EBS --------------------

# VULNERABILITY 13: EBS volume is not encrypted

resource "aws_ebs_volume" "company_data" {
  availability_zone = "ap-south-1a"
  size              = 10
  encrypted         = false

  tags = {
    Name = "Company-Data-Volume"
  }
}

# -------------------- RDS --------------------

resource "aws_db_subnet_group" "company" {
  name = "company-db-subnet-group"

  subnet_ids = [
    aws_subnet.app_a.id,
    aws_subnet.db_b.id
  ]

  tags = {
    Name = "Company-DB-Subnet-Group"
  }
}

resource "aws_security_group" "database" {
  name        = "company-database-sg"
  description = "Database access from internal network"
  vpc_id      = aws_vpc.company.id

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "company" {
  identifier        = "company-database-day2"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t3.micro"
  allocated_storage = 20

  username = "companyadmin"
  password = "Day2-Lab-Only-NotARealPassword!"

  db_subnet_group_name   = aws_db_subnet_group.company.name
  vpc_security_group_ids = [aws_security_group.database.id]

  # VULNERABILITY 14: Database is publicly accessible
  publicly_accessible = true

  # VULNERABILITY 15: Database storage is not encrypted
  storage_encrypted = false

  # VULNERABILITY 16: No backup retention
  backup_retention_period = 0

  # VULNERABILITY 17: No deletion protection
  deletion_protection = false

  skip_final_snapshot = true
  tags = {
    Name = "Company-Production-Database"
  }
}
