"""Read-only export of IAM authorization details using boto3.

This is the only module that talks to AWS. It calls a single read-only API,
``iam:GetAccountAuthorizationDetails``, and writes the result to disk so that
analysis can happen offline. boto3 is an optional dependency
(``pip install "iam-privesc-lens[aws]"``).
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

__all__ = ["fetch_authorization_details", "BotoUnavailableError"]

_LIST_KEYS = ("UserDetailList", "GroupDetailList", "RoleDetailList", "Policies")


class BotoUnavailableError(RuntimeError):
    """Raised when boto3 is not installed."""


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"cannot serialise {type(value).__name__}")


def fetch_authorization_details(
    output: str | Path, profile: str | None = None, region: str | None = None
) -> dict[str, int]:
    """Download ``get-account-authorization-details`` (all pages) to ``output``.

    Requires only the read-only ``iam:GetAccountAuthorizationDetails`` permission.

    Returns:
        Number of entries collected per list (users, groups, roles, policies).

    Raises:
        BotoUnavailableError: if boto3 is not installed.
    """
    try:
        import boto3  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise BotoUnavailableError(
            'boto3 is not installed; run: pip install "iam-privesc-lens[aws]"'
        ) from exc

    session = boto3.Session(profile_name=profile, region_name=region)
    client = session.client("iam")
    paginator = client.get_paginator("get_account_authorization_details")
    merged: dict[str, list[Any]] = {key: [] for key in _LIST_KEYS}
    for page in paginator.paginate():
        for key in _LIST_KEYS:
            merged[key].extend(page.get(key, []))
    Path(output).write_text(json.dumps(merged, indent=2, default=_json_default), encoding="utf-8")
    return {key: len(values) for key, values in merged.items()}
