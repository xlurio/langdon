import abc
from pathlib import Path

import pydantic

from langdon.langdon_manager import register_event
from langdon.models import (
    Domain,
    IpAddress,
    Technology,
    TransportLayerProtocolT,
    UsedPort,
    WebDirectory,
)


class Event(pydantic.BaseModel, abc.ABC):
    model_config = {"arbitrary_types_allowed": True}


@register_event
class VulnerabilityDiscovered(Event):
    name: str
    source: str
    technology: Technology


@register_event
class TechnologyDiscovered(Event):
    name: str
    version: str | None = None
    directory: WebDirectory | None = None
    port: UsedPort | None = None


@register_event
class DomainDiscovered(Event):
    name: str


@register_event
class IpAddressDiscovered(Event):
    address: str
    domain: Domain | None = None


@register_event
class PortDiscovered(Event):
    port: int
    transport_layer_protocol: TransportLayerProtocolT
    is_filtered: bool
    ip_address: IpAddress


@register_event
class WebDirectoryDiscovered(Event):
    path: str
    domain: Domain | None = None
    ip_address: IpAddress | None = None
    uses_ssl: bool


@register_event
class HttpHeaderDiscovered(Event):
    name: str
    web_directory: WebDirectory


@register_event
class HttpCookieDiscovered(Event):
    name: str
    web_directory: WebDirectory


@register_event
class WebDirectoryResponseDiscovered(Event):
    directory: WebDirectory
    response_hash: str
    response_path: Path
