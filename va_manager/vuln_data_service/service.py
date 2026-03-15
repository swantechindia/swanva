"""Public interface for the in-memory vulnerability data index."""

from __future__ import annotations

import logging
from threading import Lock
from collections import defaultdict

from sqlalchemy.orm import Session

from va_manager.vuln_data_service.index_store import VulnerabilityIndexStore

LOGGER = logging.getLogger(__name__)


class VulnerabilityDataService:
    """Serve exact CPE and version-range CVE lookups backed by in-memory indexes.

    The index is designed to be loaded once per worker process and then reused
    for many scan analyses. Rebuilding it for every job defeats the purpose of
    the in-memory acceleration layer, so initialization is guarded by a lock.
    """

    def __init__(self, store: VulnerabilityIndexStore | None = None) -> None:
        self.store = store or VulnerabilityIndexStore()
        self.initialized = False
        self.lock = Lock()

    def initialize(self, db: Session) -> None:
        """Build the initial in-memory index once for the current process."""

        with self.lock:
            if self.initialized:
                return

            self.store.load_index(db)
            self.initialized = True

    def lookup_cves(self, cpe_uri: str) -> list[str]:
        """Return CVE IDs for one CPE URI, including version-range matches when possible."""

        exact_matches = set(self.store.get_cves_for_cpe(cpe_uri))
        vendor, product, version = _parse_cpe_uri(cpe_uri)
        if vendor and product and version and version not in {"*", "-"}:
            exact_matches.update(self.lookup_product_version(vendor, product, version))
        return sorted(exact_matches)

    def lookup_multiple_cpes(self, cpe_list: list[str]) -> dict[str, list[str]]:
        """Return CVE IDs for multiple CPE URIs in one call."""

        results: dict[str, list[str]] = defaultdict(list)
        for cpe_uri in cpe_list:
            if not cpe_uri:
                continue
            results[cpe_uri] = self.lookup_cves(cpe_uri)
        return dict(results)

    def lookup_product_version(self, vendor: str, product: str, version: str) -> list[str]:
        """Return CVE IDs for a vendor/product/version via the version-range index."""

        if not vendor or not product or not version:
            return []

        matches = sorted(set(self.store.get_cves_for_product_version(vendor, product, version)))
        if matches:
            LOGGER.info(
                "Matched version-range vulnerabilities for %s:%s:%s count=%d",
                vendor,
                product,
                version,
                len(matches),
            )
        return matches

    def reload(self, db: Session) -> None:
        """Reload the in-memory index after feed updates."""

        LOGGER.info("Reloading vulnerability index")
        with self.lock:
            self.initialized = False
            self.store.reload_index(db)
            self.initialized = True

    def reload_indexes(self, db: Session | None = None) -> None:
        """Reload or invalidate the in-memory indexes after feed updates."""

        with self.lock:
            self.initialized = False
        if db is not None:
            self.initialize(db)

    def find_candidate_cpes(self, product_name: str) -> list[str]:
        """Return candidate CPE URIs for a normalized product name.

        Candidate lookup uses vendor/product keys derived from the vulnerability
        database itself instead of relying on a static manual name map.
        """

        lookup_key = _normalize_product_key(product_name)
        if not lookup_key:
            return []
        return self.store.get_candidate_cpes(lookup_key)

    def match_vulnerabilities(self, product_name: str, version: str) -> list[str]:
        """Return unique CVE IDs for a normalized product/version pair."""

        if not product_name or not version:
            return []

        cve_ids: set[str] = set()
        vendor_product_pairs: set[tuple[str, str]] = set()

        for candidate_cpe in self.find_candidate_cpes(product_name):
            vendor, product, _ = _parse_cpe_uri(candidate_cpe)
            if not vendor or not product:
                continue

            vendor_product_pairs.add((vendor, product))
            cve_ids.update(self.store.get_cves_for_cpe(_build_cpe_uri(vendor, product, version)))
            cve_ids.update(self.store.get_cves_for_cpe(_build_cpe_uri(vendor, product, "*")))

        for vendor, product in vendor_product_pairs:
            cve_ids.update(self.lookup_product_version(vendor, product, version))

        return sorted(cve_ids)


def _parse_cpe_uri(cpe_uri: str) -> tuple[str | None, str | None, str | None]:
    """Extract vendor, product, and version tokens from a CPE URI."""

    parts = str(cpe_uri or "").split(":")
    if len(parts) < 6:
        return None, None, None

    vendor = parts[3].strip() or None
    product = parts[4].strip() or None
    version = parts[5].strip() or None
    return vendor, product, version


def _build_cpe_uri(vendor: str, product: str, version: str) -> str:
    """Build a canonical application CPE 2.3 URI for lookup purposes."""

    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def _normalize_product_key(product_name: str) -> str:
    """Normalize product names for candidate lookup against the product index."""

    text = str(product_name or "").strip().lower()
    if ":" in text:
        vendor, _, product = text.partition(":")
        vendor_text = " ".join(vendor.replace("_", " ").split())
        product_text = "_".join(product.replace(" ", "_").split())
        return f"{vendor_text}:{product_text}".strip(":")
    return " ".join(text.replace("_", " ").split())


vulnerability_data_service = VulnerabilityDataService()
