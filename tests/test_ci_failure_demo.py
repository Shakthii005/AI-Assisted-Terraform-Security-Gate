
"""
Day 7: Intentional CI failure simulation.

This test deliberately fails to demonstrate
that GitHub Actions detects broken tests.
"""


def test_ci_detects_intentional_failure():
    assert False, "Intentional Day 7 CI failure simulation"
