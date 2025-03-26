from typing import TypeVar

from langdon.event_handlers import (
    domain_discovered_handler,
    technology_discovered_handler,
    vulnerability_discovered_handler,
)
from langdon.events import (
    DomainDiscovered,
    Event,
    TechnologyDiscovered,
    VulnerabilityDiscovered,
)
from langdon.langdon_manager import LangdonManager

EVENT_HANDLERS_MAPPING = {
    VulnerabilityDiscovered: vulnerability_discovered_handler.handle_event,
    TechnologyDiscovered: technology_discovered_handler.handle_event,
    DomainDiscovered: domain_discovered_handler.handle_event,
}


T = TypeVar("T", bound="Event")


def dispatch_event(event: T, *, manager: LangdonManager) -> None:
    handler = EVENT_HANDLERS_MAPPING.get(type(event))

    if handler is not None:
        handler(event, manager=manager)
    else:
        raise ValueError(f"No handler for event {event}")
