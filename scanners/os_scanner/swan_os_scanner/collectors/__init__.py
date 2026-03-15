"""Collector modules for the OS credential scanner."""

from swan_os_scanner.collectors.cron import collect_cron
from swan_os_scanner.collectors.kernel import collect_kernel
from swan_os_scanner.collectors.network import collect_network
from swan_os_scanner.collectors.os_info import collect_os_info
from swan_os_scanner.collectors.packages import collect_packages
from swan_os_scanner.collectors.permissions import collect_permissions
from swan_os_scanner.collectors.services import collect_services
from swan_os_scanner.collectors.software import collect_software
from swan_os_scanner.collectors.sudo import collect_sudo
from swan_os_scanner.collectors.users import collect_users

__all__ = [
    "collect_cron",
    "collect_kernel",
    "collect_network",
    "collect_os_info",
    "collect_packages",
    "collect_permissions",
    "collect_services",
    "collect_software",
    "collect_sudo",
    "collect_users",
]
