"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from iam_privesc_lens.model import Account, load_data, load_file

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def multihop_account() -> Account:
    return load_file(FIXTURES / "multihop-account.json")


@pytest.fixture
def example_account() -> Account:
    return load_file(ROOT / "examples" / "vulnerable-account.json")


def policy(*statements: dict) -> Account:
    """Build a single-policy account from statements."""
    return load_data({"Version": "2012-10-17", "Statement": list(statements)}, label="test")
