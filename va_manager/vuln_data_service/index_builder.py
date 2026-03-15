"""Build optimized in-memory exact and range-based vulnerability indexes."""

from __future__ import annotations

from collections import defaultdict

from va_manager.vuln_data_service.models import VersionRange


def build_cpe_index(cpe_entries: list[tuple[str, str]]) -> dict[str, tuple[str, ...]]:
    """Build a deduplicated CPE-to-CVE mapping for O(1) lookups."""

    index: dict[str, list[str]] = defaultdict(list)
    seen_pairs: set[tuple[str, str]] = set()

    for cpe_uri, cve_id in cpe_entries:
        if not cpe_uri or not cve_id:
            continue

        key = (cpe_uri, cve_id)
        if key in seen_pairs:
            continue

        seen_pairs.add(key)
        index[cpe_uri].append(cve_id)

    return {cpe_uri: tuple(cve_ids) for cpe_uri, cve_ids in index.items()}


def build_version_range_index(
    version_ranges: list[VersionRange],
) -> dict[str, tuple[VersionRange, ...]]:
    """Build a vendor/product-to-version-ranges mapping for efficient lookups."""

    index: dict[str, list[VersionRange]] = defaultdict(list)
    seen_ranges: set[tuple[str, str, str | None, bool | None, str | None, bool | None, str]] = set()

    for version_range in version_ranges:
        if not version_range.vendor or not version_range.product or not version_range.cve_id:
            continue

        key = (
            version_range.vendor,
            version_range.product,
            version_range.version_start,
            version_range.version_start_inclusive,
            version_range.version_end,
            version_range.version_end_inclusive,
            version_range.cve_id,
        )
        if key in seen_ranges:
            continue

        seen_ranges.add(key)
        product_key = f"{version_range.vendor}:{version_range.product}"
        index[product_key].append(version_range)

    return {product_key: tuple(ranges) for product_key, ranges in index.items()}


def build_product_cpe_index(
    product_entries: list[tuple[str | None, str | None, str]],
) -> dict[str, tuple[str, ...]]:
    """Build normalized product-name lookup keys that point to candidate CPE URIs."""

    index: dict[str, list[str]] = defaultdict(list)
    seen_pairs: set[tuple[str, str]] = set()

    for vendor, product, cpe_uri in product_entries:
        if not vendor or not product or not cpe_uri:
            continue

        for token in _candidate_tokens(vendor, product):
            key = (token, cpe_uri)
            if key in seen_pairs:
                continue
            seen_pairs.add(key)
            index[token].append(cpe_uri)

    return {token: tuple(cpes) for token, cpes in index.items()}


def _candidate_tokens(vendor: str, product: str) -> set[str]:
    """Generate normalized lookup keys for one vendor/product pair."""

    normalized_vendor = _normalize_lookup_key(vendor)
    normalized_product = _normalize_lookup_key(product)
    product_words = normalized_product.replace("_", " ")

    candidates = {
        normalized_vendor,
        normalized_product,
        product_words,
        f"{normalized_vendor}:{normalized_product.replace(' ', '_')}",
        _normalize_lookup_key(f"{normalized_vendor} {normalized_product}"),
        _normalize_lookup_key(f"{normalized_vendor} {product_words}"),
    }
    return {candidate for candidate in candidates if candidate}


def _normalize_lookup_key(value: str) -> str:
    """Normalize product tokens for case-insensitive candidate lookup."""

    text = str(value or "").strip().lower()
    if ":" in text:
        vendor, _, product = text.partition(":")
        vendor_text = " ".join(vendor.replace("_", " ").split())
        product_text = "_".join(product.replace(" ", "_").split())
        return f"{vendor_text}:{product_text}".strip(":")
    return " ".join(text.replace("_", " ").split())
