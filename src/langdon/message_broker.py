from typing import TypeVar

from langdon.event_handlers import (
    domain_discovered_handler,
    ip_address_discovered_handler,
    port_discovered_handler,
    technology_discovered_handler,
    vulnerability_discovered_handler,
    web_directory_discovered_handler,
    web_directory_response_discovered_handler,
)
from langdon.events import (
    DomainDiscovered,
    Event,
    IpAddressDiscovered,
    PortDiscovered,
    TechnologyDiscovered,
    VulnerabilityDiscovered,
    WebDirectoryDiscovered,
    WebDirectoryResponseDiscovered,
)
from langdon.langdon_manager import LangdonManager

EVENT_HANDLERS_MAPPING = {
    VulnerabilityDiscovered: vulnerability_discovered_handler.handle_event,
    TechnologyDiscovered: technology_discovered_handler.handle_event,
    DomainDiscovered: domain_discovered_handler.handle_event,
    IpAddressDiscovered: ip_address_discovered_handler.handle_event,
    PortDiscovered: port_discovered_handler.handle_event,
    WebDirectoryDiscovered: web_directory_discovered_handler.handle_event,
    WebDirectoryResponseDiscovered: web_directory_response_discovered_handler.handle_event,
}


T = TypeVar("T", bound="Event")


def dispatch_event(event: T, *, manager: LangdonManager) -> None:
    EVENT_HANDLERS_MAPPING[type(event)](event, manager=manager)
