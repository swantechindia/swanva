"""Global in-memory storage for exact and version-range vulnerability indexes."""

from __future__ import annotations

import logging
from threading import RLock

from sqlalchemy.orm import Session

from va_manager.vuln_data_service.index_builder import (
    build_cpe_index,
    build_product_cpe_index,
    build_version_range_index,
)
from va_manager.vuln_data_service.loader import (
    load_cpe_entries,
    load_product_cpe_entries,
    load_version_ranges,
)
from va_manager.vuln_data_service.models import IndexedVulnerability
from va_manager.vuln_data_service.version_matcher import version_in_range

LOGGER = logging.getLogger(__name__)


class VulnerabilityIndexStore:
    """Thread-safe in-memory store for exact and version-range vulnerability indexes."""

    def __init__(self) -> None:
        self._index = IndexedVulnerability()
        self._lock = RLock()

    def load_index(self, db: Session) -> IndexedVulnerability:
        """Load vulnerability indexes from the database into memory."""

        LOGGER.info("Starting vulnerability index build")
        cpe_entries = load_cpe_entries(db)
        version_ranges = load_version_ranges(db)
        product_entries = load_product_cpe_entries(db)
        index = IndexedVulnerability(
            exact_cpe_index=build_cpe_index(cpe_entries),
            version_range_index=build_version_range_index(version_ranges),
            product_cpe_index=build_product_cpe_index(product_entries),
        )
        with self._lock:
            self._index = index
        LOGGER.info(
            "Completed vulnerability index build: cpe_keys=%d version_ranges=%d product_keys=%d unique_cves=%d",
            index.total_cpes,
            index.total_ranges,
            index.total_products,
            index.total_cves,
        )
        return index

    def get_cves_for_cpe(self, cpe_uri: str) -> list[str]:
        """Return CVE IDs for an exact CPE URI from the in-memory index."""

        with self._lock:
            return list(self._index.exact_cpe_index.get(cpe_uri, ()))

    def get_cves_for_product_version(self, vendor: str, product: str, version: str) -> list[str]:
        """Return CVE IDs for one vendor/product/version via the range index."""

        product_key = f"{vendor}:{product}"
        with self._lock:
            version_ranges = self._index.version_range_index.get(product_key, ())

        return [
            version_range.cve_id
            for version_range in version_ranges
            if version_in_range(version, version_range)
        ]

    def get_candidate_cpes(self, product_name: str) -> list[str]:
        """Return candidate CPE URIs for a normalized product name."""

        with self._lock:
            return list(self._index.product_cpe_index.get(product_name, ()))

    def reload_index(self, db: Session) -> IndexedVulnerability:
        """Refresh the in-memory index from the database."""

        return self.load_index(db)
