
from pathlib import Path

from gate.extract import ExtractedResource
from gate.diff_guard import verify_resource_scope


ORIGINAL_SSH = '''resource "aws_security_group" "ssh_open" {
  name = "company-ssh-open"
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}'''


PATCHED_SSH = '''resource "aws_security_group" "ssh_open" {
  name = "company-ssh-open"
}'''


ORIGINAL_RDS = '''resource "aws_db_instance" "company" {
  publicly_accessible = true
}'''


def create_fixture(tmp_path):
    original = tmp_path / "original"
    patched = tmp_path / "patched"

    original.mkdir()
    patched.mkdir()

    source = (
        ORIGINAL_SSH
        + "\n\n"
        + ORIGINAL_RDS
        + "\n"
    )

    original_file = original / "network.tf"
    patched_file = patched / "network.tf"

    original_file.write_text(source, encoding="utf-8")
    patched_file.write_text(source, encoding="utf-8")

    extracted = ExtractedResource(
        file_path=original_file,
        resource="aws_security_group.ssh_open",
        start_line=1,
        end_line=8,
        resource_block=ORIGINAL_SSH,
        context_before="",
        context_after=ORIGINAL_RDS,
    )

    proposal = {
        "patched_block": PATCHED_SSH,
        "additional_blocks": [],
        "explanation": "Remove public SSH access.",
    }

    return original, patched, extracted, proposal


def test_expected_resource_change_is_accepted(tmp_path):
    original, patched, extracted, proposal = create_fixture(tmp_path)

    source = (
        original / "network.tf"
    ).read_text(encoding="utf-8")

    expected = source.replace(
        ORIGINAL_SSH,
        PATCHED_SSH,
        1,
    )

    (patched / "network.tf").write_text(
        expected,
        encoding="utf-8",
    )

    result = verify_resource_scope(
        original,
        patched,
        "network.tf",
        extracted,
        proposal,
    )

    assert result["passed"] is True
    assert result["unexpected_modified"] == []
    assert result["removed_resources"] == []


def test_unrelated_resource_change_is_rejected(tmp_path):
    original, patched, extracted, proposal = create_fixture(tmp_path)

    source = (
        original / "network.tf"
    ).read_text(encoding="utf-8")

    expected = source.replace(
        ORIGINAL_SSH,
        PATCHED_SSH,
        1,
    )

    # Simulate AI secretly modifying the RDS resource.
    tampered = expected.replace(
        "publicly_accessible = true",
        "publicly_accessible = false",
    )

    (patched / "network.tf").write_text(
        tampered,
        encoding="utf-8",
    )

    result = verify_resource_scope(
        original,
        patched,
        "network.tf",
        extracted,
        proposal,
    )

    assert result["passed"] is False
    assert result["unexpected_modified"] != []
    assert result["exact_target_file_match"] is False


def test_approved_additional_resource_is_accepted(tmp_path):
    original = tmp_path / "original"
    patched = tmp_path / "patched"

    original.mkdir()
    patched.mkdir()

    original_block = '''resource "aws_s3_bucket" "company_data" {
  bucket = "company-data-demo"
}'''

    additional_block = '''resource "aws_s3_bucket_server_side_encryption_configuration" "company_data" {
  bucket = aws_s3_bucket.company_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}'''

    original_file = original / "storage.tf"
    patched_file = patched / "storage.tf"

    original_file.write_text(
        original_block + "\n",
        encoding="utf-8",
    )

    patched_file.write_text(
        original_block
        + "\n\n"
        + additional_block
        + "\n",
        encoding="utf-8",
    )

    extracted = ExtractedResource(
        file_path=original_file,
        resource="aws_s3_bucket.company_data",
        start_line=1,
        end_line=3,
        resource_block=original_block,
        context_before="",
        context_after="",
    )

    proposal = {
        "patched_block": original_block,
        "additional_blocks": [additional_block],
        "explanation": "Add default KMS encryption.",
    }

    result = verify_resource_scope(
        original,
        patched,
        "storage.tf",
        extracted,
        proposal,
    )

    assert result["passed"] is True
    assert result["actual_added"] == result["expected_added"]
