import abc
from pathlib import Path

import pydantic

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


class VulnerabilityDiscovered(Event):
    name: str
    source: str
    technology: Technology


class TechnologyDiscovered(Event):
    name: str
    version: str | None = None
    directory: WebDirectory | None = None
    port: UsedPort | None = None


class DomainDiscovered(Event):
    name: str


class IpAddressDiscovered(Event):
    address: str
    domain: Domain | None = None


class PortDiscovered(Event):
    port: int
    transport_layer_protocol: TransportLayerProtocolT
    is_filtered: bool
    ip_address: IpAddress


class WebDirectoryDiscovered(Event):
    path: str
    domain: Domain | None = None
    ip_address: IpAddress | None = None
    uses_ssl: bool


class HttpHeaderDiscovered(Event):
    name: str
    web_directory: WebDirectory


class HttpCookieDiscovered(Event):
    name: str
    web_directory: WebDirectory


class WebDirectoryResponseDiscovered(Event):
    directory: WebDirectory
    response_hash: str
    response_path: Path
