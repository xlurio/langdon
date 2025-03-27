from __future__ import annotations

import abc
from typing import TYPE_CHECKING

import pydantic

from langdon.langdon_manager import register_event

if TYPE_CHECKING:
    from langdon.models import (
        Domain,
        IpAddress,
        Technology,
        TransportLayerProtocolT,
        UsedPort,
        WebDirectory,
    )


class Event(pydantic.BaseModel, abc.ABC): ...


@register_event
class VulnerabilityDiscovered(Event):
    name: str
    source: str
    technology: Technology


@register_event
class TechnologyDiscovered(Event):
    name: str
    version: str | None
    directory: WebDirectory | None
    port: UsedPort | None


@register_event
class DomainDiscovered(Event):
    name: str


@register_event
class IpAddressDiscovered(Event):
    address: str
    domain: Domain | None


@register_event
class PortDiscovered(Event):
    port: int
    transport_layer_protocol: TransportLayerProtocolT
    is_filtered: bool
    ip_address: IpAddress


@register_event
class WebDirectoryDiscovered(Event):
    path: str
    domain: Domain
