"""Helpers for matching complex software versions against vulnerability ranges.

This matcher tokenizes numeric and alphabetic segments so it can compare common
package version styles such as:
- 1.1.1f
- 7.2p2
- 2.4.49-rc1
- 1:2.3.4-1ubuntu2
"""

from __future__ import annotations

import re
from typing import cast

from va_manager.vuln_data_service.models import VersionRange

PRE_RELEASE_MARKERS = {"a", "alpha", "b", "beta", "pre", "preview", "rc"}
POST_RELEASE_MARKERS = {"p", "pl", "patch", "ubuntu", "deb", "el", "rhel"}


def version_in_range(
    version: str,
    start_or_range: str | VersionRange | None = None,
    end: str | None = None,
    start_inclusive: bool | None = True,
    end_inclusive: bool | None = True,
) -> bool:
    """Return whether a version falls inside the provided vulnerable range."""

    normalized_version = _normalize_version(version)
    if not normalized_version:
        return False

    if isinstance(start_or_range, VersionRange):
        range_object = start_or_range
        start = range_object.version_start
        end = range_object.version_end
        start_inclusive = range_object.version_start_inclusive
        end_inclusive = range_object.version_end_inclusive
    else:
        start = start_or_range

    if start:
        lower_compare = compare_versions(normalized_version, start)
        if lower_compare < 0:
            return False
        if lower_compare == 0 and start_inclusive is False:
            return False

    if end:
        upper_compare = compare_versions(normalized_version, end)
        if upper_compare > 0:
            return False
        if upper_compare == 0 and end_inclusive is False:
            return False

    return True


def parse_version_tokens(version: str) -> list[int | str]:
    """Tokenize a version string into comparable numeric and alpha segments."""

    normalized = _normalize_version(version)
    if not normalized:
        return []

    tokens: list[int | str] = []
    for token in re.findall(r"\d+|[a-z]+", normalized):
        if token.isdigit():
            tokens.append(int(token))
        else:
            tokens.append(token)
    return tokens


def compare_versions(left: str, right: str) -> int:
    """Compare two version strings using numeric and semantic marker ordering."""

    left_tokens = parse_version_tokens(left)
    right_tokens = parse_version_tokens(right)
    max_length = max(len(left_tokens), len(right_tokens))

    for index in range(max_length):
        left_missing = index >= len(left_tokens)
        right_missing = index >= len(right_tokens)

        if left_missing and right_missing:
            return 0
        if left_missing:
            return _missing_side_result(cast(list[int | str], right_tokens[index:]), missing_is_left=True)
        if right_missing:
            return _missing_side_result(cast(list[int | str], left_tokens[index:]), missing_is_left=False)

        left_token = left_tokens[index]
        right_token = right_tokens[index]
        if left_token == right_token:
            continue

        if isinstance(left_token, int) and isinstance(right_token, int):
            return -1 if left_token < right_token else 1

        if isinstance(left_token, int):
            return 1
        if isinstance(right_token, int):
            return -1

        left_text = cast(str, left_token)
        right_text = cast(str, right_token)
        if left_text in PRE_RELEASE_MARKERS and right_text not in PRE_RELEASE_MARKERS:
            return -1
        if right_text in PRE_RELEASE_MARKERS and left_text not in PRE_RELEASE_MARKERS:
            return 1
        if left_text in POST_RELEASE_MARKERS and right_text not in POST_RELEASE_MARKERS:
            return 1
        if right_text in POST_RELEASE_MARKERS and left_text not in POST_RELEASE_MARKERS:
            return -1
        return -1 if left_text < right_text else 1

    return 0


def _missing_side_result(remaining_tokens: list[int | str], missing_is_left: bool) -> int:
    """Resolve comparison when one version has additional trailing tokens."""

    for token in remaining_tokens:
        if isinstance(token, int):
            if token == 0:
                continue
            return -1 if missing_is_left else 1

        if token in PRE_RELEASE_MARKERS:
            return 1 if missing_is_left else -1
        if token in POST_RELEASE_MARKERS:
            return -1 if missing_is_left else 1
        return -1 if missing_is_left else 1

    return 0


def _normalize_version(version: str) -> str:
    """Normalize raw version text into a comparable token string."""

    return str(version or "").strip().lower()
