"""Collector modules for the OS credential scanner."""

from os_scanner.collectors.kernel import collect_kernel
from os_scanner.collectors.os_info import collect_os_info
from os_scanner.collectors.packages import collect_packages
from os_scanner.collectors.services import collect_services
from os_scanner.collectors.users import collect_users

__all__ = [
    "collect_kernel",
    "collect_os_info",
    "collect_packages",
    "collect_services",
    "collect_users",
]
