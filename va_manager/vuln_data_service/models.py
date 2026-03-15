"""Lightweight data models for indexed vulnerability lookups."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class IndexedCVE:
    """Minimal immutable CVE identifier wrapper."""

    cve_id: str


@dataclass(frozen=True, slots=True)
class VersionRange:
    """Indexed vulnerable version range for one vendor/product pair."""

    vendor: str
    product: str
    version_start: str | None
    version_start_inclusive: bool | None
    version_end: str | None
    version_end_inclusive: bool | None
    cve_id: str


@dataclass(slots=True)
class IndexedVulnerability:
    """In-memory representation of exact and range-based vulnerability indexes."""

    exact_cpe_index: dict[str, tuple[str, ...]] = field(default_factory=dict)
    version_range_index: dict[str, tuple[VersionRange, ...]] = field(default_factory=dict)
    product_cpe_index: dict[str, tuple[str, ...]] = field(default_factory=dict)

    @property
    def cpe_index(self) -> dict[str, tuple[str, ...]]:
        """Backward-compatible alias for the exact CPE index."""

        return self.exact_cpe_index

    @property
    def total_cpes(self) -> int:
        """Return the number of indexed CPE keys."""

        return len(self.exact_cpe_index)

    @property
    def total_ranges(self) -> int:
        """Return the number of indexed version ranges."""

        return sum(len(values) for values in self.version_range_index.values())

    @property
    def total_products(self) -> int:
        """Return the number of normalized product lookup keys."""

        return len(self.product_cpe_index)

    @property
    def total_cves(self) -> int:
        """Return the count of unique CVE IDs referenced by the index."""

        unique_ids = {cve_id for values in self.exact_cpe_index.values() for cve_id in values}
        for values in self.version_range_index.values():
            unique_ids.update(version_range.cve_id for version_range in values)
        return len(unique_ids)
