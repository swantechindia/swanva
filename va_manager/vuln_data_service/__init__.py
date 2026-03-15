"""High-performance in-memory vulnerability indexing service."""

from va_manager.vuln_data_service.service import VulnerabilityDataService
from va_manager.vuln_data_service.version_matcher import version_in_range

__all__ = ["VulnerabilityDataService", "version_in_range"]
