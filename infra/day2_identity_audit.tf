
# ============================================================
# DAY 2 - IAM, CLOUDTRAIL, KMS AND FAKE SECRET
# INTENTIONALLY VULNERABLE - DO NOT DEPLOY
# ============================================================

# -------------------- IAM --------------------

resource "aws_iam_user" "legacy" {
  name = "company-legacy-user"
}

# VULNERABILITY 19: Overly permissive IAM policy
resource "aws_iam_policy" "wildcard_admin" {
  name        = "Company-Wildcard-Policy"
  description = "Intentionally excessive permissions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "legacy_admin" {
  user       = aws_iam_user.legacy.name
  policy_arn = aws_iam_policy.wildcard_admin.arn
}

# VULNERABILITY 20: Inline user policy
resource "aws_iam_user_policy" "legacy_inline" {
  name = "company-inline-policy"
  user = aws_iam_user.legacy.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "arn:aws:s3:::company-internal-data/*"
      }
    ]
  })
}

# VULNERABILITY 21: No account password policy resource configured


# -------------------- CLOUDTRAIL --------------------

resource "aws_cloudtrail" "company_audit" {
  name           = "company-audit-trail"
  s3_bucket_name = aws_s3_bucket.company_data.id

  include_global_service_events = true

  # VULNERABILITY 22: Not a multi-region trail
  is_multi_region_trail = false

  # VULNERABILITY 23: Log file validation disabled
  enable_log_file_validation = false

  # VULNERABILITY 24: No KMS encryption key configured
}


# -------------------- KMS --------------------

resource "aws_kms_key" "company" {
  description             = "Company data encryption key"
  deletion_window_in_days = 7

  # VULNERABILITY 25: Automatic key rotation disabled
  enable_key_rotation = false

  tags = {
    Name = "Company-KMS-Key"
  }
}


# -------------------- FAKE HARDCODED CREDENTIAL --------------------

# VULNERABILITY 26: Hardcoded AWS example credentials
# These are public AWS documentation examples, NOT real credentials.
# Never replace them with actual credentials.

locals {
  legacy_aws_access_key_id     = "AKIAIOSFODNN7EXAMPLE"
  legacy_aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}
