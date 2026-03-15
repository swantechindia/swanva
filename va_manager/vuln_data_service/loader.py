"""Load exact and version-range vulnerability mappings from the database."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from va_manager.vuln_data_service.models import VersionRange
from va_manager.vulnerability_engine.database.models import CPEEntry, CPEDictionaryEntry


def load_cpe_entries(db: Session) -> list[tuple[str, str]]:
    """Load exact CPE-to-CVE mappings from the vulnerability database."""

    stmt = (
        select(CPEEntry.cpe_uri, CPEEntry.cve_id)
        .where(CPEEntry.version_start.is_(None), CPEEntry.version_end.is_(None))
        .order_by(CPEEntry.cpe_uri.asc(), CPEEntry.cve_id.asc())
    )
    return [(cpe_uri, cve_id) for cpe_uri, cve_id in db.execute(stmt).all()]


def load_version_ranges(db: Session) -> list[VersionRange]:
    """Load vendor/product version ranges from the vulnerability database."""

    stmt = (
        select(
            CPEEntry.vendor,
            CPEEntry.product,
            CPEEntry.version_start,
            CPEEntry.version_start_including,
            CPEEntry.version_end,
            CPEEntry.version_end_including,
            CPEEntry.cve_id,
        )
        .where(CPEEntry.vendor.is_not(None), CPEEntry.product.is_not(None))
        .where(CPEEntry.version_start.is_not(None) | CPEEntry.version_end.is_not(None))
        .order_by(CPEEntry.vendor.asc(), CPEEntry.product.asc(), CPEEntry.cve_id.asc())
    )

    return [
        VersionRange(
            vendor=str(vendor),
            product=str(product),
            version_start=str(version_start) if version_start is not None else None,
            version_start_inclusive=version_start_including,
            version_end=str(version_end) if version_end is not None else None,
            version_end_inclusive=version_end_including,
            cve_id=str(cve_id),
        )
        for vendor, product, version_start, version_start_including, version_end, version_end_including, cve_id in db.execute(stmt).all()
        if vendor and product and cve_id
    ]


def load_product_cpe_entries(db: Session) -> list[tuple[str | None, str | None, str]]:
    """Load vendor/product-to-CPE mappings for candidate lookup.

    The dictionary combines observed vulnerability CPEs with the official CPE
    dictionary so correlation can discover candidates even when a product has
    not appeared in the local vulnerability dataset yet.
    """

    stmt = (
        select(CPEEntry.vendor, CPEEntry.product, CPEEntry.cpe_uri)
        .where(CPEEntry.cpe_uri.is_not(None))
        .where(CPEEntry.vendor.is_not(None), CPEEntry.product.is_not(None))
        .order_by(CPEEntry.vendor.asc(), CPEEntry.product.asc(), CPEEntry.cpe_uri.asc())
    )
    return [
        (vendor, product, cpe_uri)
        for vendor, product, cpe_uri in db.execute(stmt).all()
        if vendor and product and cpe_uri
    ] + [
        (vendor, product, cpe_uri)
        for vendor, product, cpe_uri in db.execute(
            select(CPEDictionaryEntry.vendor, CPEDictionaryEntry.product, CPEDictionaryEntry.cpe_uri)
            .where(CPEDictionaryEntry.deprecated.is_(False))
            .where(CPEDictionaryEntry.vendor.is_not(None), CPEDictionaryEntry.product.is_not(None))
            .order_by(CPEDictionaryEntry.vendor.asc(), CPEDictionaryEntry.product.asc(), CPEDictionaryEntry.cpe_uri.asc())
        ).all()
        if vendor and product and cpe_uri
    ]
