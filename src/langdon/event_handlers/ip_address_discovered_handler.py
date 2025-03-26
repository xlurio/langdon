from __future__ import annotations

from typing import TYPE_CHECKING

from langdon.models import IpAddress
from langdon.utils import create_if_not_exist

if TYPE_CHECKING:
    from langdon.events import IpAddressDiscovered
    from langdon.langdon_manager import LangdonManager
    from langdon.models import IpAddressVersionT


def _detect_ip_version(ip_address: str) -> IpAddressVersionT:
    if ":" in ip_address:
        return "ipv6"
    return "ipv4"


def handle_event(event: IpAddressDiscovered, *, manager: LangdonManager) -> None:
    ip_version = _detect_ip_version(event.address)

    if not create_if_not_exist(
        IpAddress,
        address=event.address,
        defaults={"version": ip_version},
        manager=manager,
    ):
        return
    
    # TODO
