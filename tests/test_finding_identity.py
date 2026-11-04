
from types import SimpleNamespace

from gate.finding_identity import (
    normalize_file_path,
    finding_key,
)


def test_windows_relative_path_normalizes():

    assert normalize_file_path(
        r"\day2_compute_database.tf"
    ) == "day2_compute_database.tf"


def test_linux_infra_path_normalizes():

    assert normalize_file_path(
        "infra/day2_compute_database.tf"
    ) == "day2_compute_database.tf"


def test_linux_absolute_infra_path_normalizes():

    assert normalize_file_path(
        "/infra/day2_compute_database.tf"
    ) == "day2_compute_database.tf"


def test_windows_absolute_infra_path_normalizes():

    assert normalize_file_path(
        r"D:\project\infra\day2_compute_database.tf"
    ) == "day2_compute_database.tf"


def test_finding_identity_is_platform_independent():

    windows_finding = SimpleNamespace(
        check_id="CKV_AWS_24",
        resource="aws_security_group.ssh_open",
        file_path=r"\day2_s3_network.tf",
    )

    linux_finding = SimpleNamespace(
        check_id="CKV_AWS_24",
        resource="aws_security_group.ssh_open",
        file_path="infra/day2_s3_network.tf",
    )

    assert finding_key(windows_finding) == finding_key(linux_finding)
