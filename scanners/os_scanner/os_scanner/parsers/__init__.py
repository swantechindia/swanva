"""Parser helpers for raw collector command output."""

from os_scanner.parsers.dpkg_parser import parse_dpkg_output
from os_scanner.parsers.rpm_parser import parse_rpm_output

__all__ = ["parse_dpkg_output", "parse_rpm_output"]
